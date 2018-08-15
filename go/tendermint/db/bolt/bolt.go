// Package bolt implements a tendermint DB, backed by BoltDB.
package bolt

import (
	"strconv"
	"sync"

	bolt "github.com/coreos/bbolt"
	dbm "github.com/tendermint/tendermint/libs/db"

	"github.com/oasislabs/ekiden/go/common/logging"
)

const dbVersion = 0

var (
	bktContents = []byte("contents")

	_ dbm.DB       = (*boltDBImpl)(nil)
	_ dbm.Iterator = (*boltDBIterator)(nil)
	_ dbm.Batch    = (*boltDBBatch)(nil)
)

type boltDBImpl struct {
	logger *logging.Logger

	db *bolt.DB

	closeOnce sync.Once
}

// New constructs a new tendermint DB, backed by a BoltDB database
// at the provided path.
//
// Note: This should only be used by tendermint, all other places
// that need a K/V store should favor using BoltDB directly.
func New(fn string) (dbm.DB, error) {
	db, err := bolt.Open(fn, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bktContents)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &boltDBImpl{
		logger: logging.GetLogger("tendermint/db/bolt"),
		db:     db,
	}, nil
}

func (d *boltDBImpl) Get(key []byte) []byte {
	k := toBoltDBKey(key)

	var v []byte
	if err := d.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktContents)

		if value := bkt.Get(k); value != nil {
			v = append([]byte{}, value...)
		}

		return nil
	}); err != nil {
		d.logger.Error("Get() failed",
			"err", err,
			"key", key,
		)
		panic(err)
	}

	return v
}

func (d *boltDBImpl) Has(key []byte) bool {
	k := toBoltDBKey(key)

	var exists bool
	if err := d.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktContents)

		value := bkt.Get(k)
		exists = value != nil

		return nil
	}); err != nil {
		d.logger.Error("Has() failed",
			"err", err,
			"key", key,
		)
		panic(err)
	}

	return exists
}

func (d *boltDBImpl) Set(key, value []byte) {
	k := toBoltDBKey(key)

	if err := d.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktContents)

		return bkt.Put(k, value)
	}); err != nil {
		d.logger.Error("Set() failed",
			"err", err,
			"key", key,
			"value", value,
		)
		panic(err)
	}
}

func (d *boltDBImpl) SetSync(key, value []byte) {
	d.Set(key, value)
	d.sync()
}

func (d *boltDBImpl) Delete(key []byte) {
	k := toBoltDBKey(key)

	if err := d.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktContents)

		return bkt.Delete(k)
	}); err != nil {
		d.logger.Error("Delete() failed",
			"err", err,
			"key", key,
		)
		panic(err)
	}
}

func (d *boltDBImpl) DeleteSync(key []byte) {
	d.Delete(key)
	d.sync()
}

func (d *boltDBImpl) Iterator(start, end []byte) dbm.Iterator {
	return d.newIterator(start, end, true)
}

func (d *boltDBImpl) ReverseIterator(start, end []byte) dbm.Iterator {
	return d.newIterator(start, end, false)
}

func (d *boltDBImpl) Close() {
	d.closeOnce.Do(func() {
		if d.db != nil {
			if err := d.db.Close(); err != nil {
				d.logger.Error("Close() failed to close BoltDB database",
					"err", err,
				)
			}
			d.db = nil
		}
	})
}
func (d *boltDBImpl) NewBatch() dbm.Batch {
	return &boltDBBatch{db: d}
}

func (d *boltDBImpl) Print() {
	// There's better ways to dump a BoltDB database...
	d.logger.Debug("Print() refusing to dump the database")
}

func (d *boltDBImpl) Stats() map[string]string {
	m := make(map[string]string)
	m["database.type"] = "BoltDB"

	info := d.db.Info()
	m["database.page_size"] = strconv.Itoa(info.PageSize)

	stats := d.db.Stats()

	// Freelist stats.
	m["database.free_page.count"] = strconv.Itoa(stats.FreePageN)
	m["database.free_page.pending"] = strconv.Itoa(stats.PendingPageN)
	m["database.free_page.allocated"] = strconv.Itoa(stats.FreeAlloc)
	m["database.free_page.total_bytes"] = strconv.Itoa(stats.FreelistInuse)

	// Transaction stats.
	m["database.tx.read.started"] = strconv.Itoa(stats.TxN)
	m["database.tx.read.open"] = strconv.Itoa(stats.OpenTxN)

	m["database.tx.page.allocations"] = strconv.Itoa(stats.TxStats.PageCount)
	m["database.tx.page.total_bytes"] = strconv.Itoa(stats.TxStats.PageAlloc)

	m["database.tx.cursors"] = strconv.Itoa(stats.TxStats.CursorCount)

	m["database.tx.node.allocations"] = strconv.Itoa(stats.TxStats.NodeCount)
	m["database.tx.node.dereferences"] = strconv.Itoa(stats.TxStats.NodeDeref)

	m["database.tx.rebalance.count"] = strconv.Itoa(stats.TxStats.Rebalance)
	m["database.tx.rebalance.time"] = stats.TxStats.RebalanceTime.String()

	m["database.tx.node.split.count"] = strconv.Itoa(stats.TxStats.Split)
	m["database.tx.node.spill.count"] = strconv.Itoa(stats.TxStats.Spill)
	m["database.tx.node.spill.time"] = stats.TxStats.SpillTime.String()

	m["database.tx.write.count"] = strconv.Itoa(stats.TxStats.Write)
	m["database.tx.write.time"] = stats.TxStats.WriteTime.String()

	return m
}

func (d *boltDBImpl) sync() {
	// The BoltDB documentation says this is unneccesary, unless the
	// `NoSync` option is used.  If it turns out to be needed for
	// some reason due to how Tendermint uses the API, then call
	// `d.db.Sync()` here.
}

func (d *boltDBImpl) writeBatch(batch *boltDBBatch) error {
	err := d.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktContents)

		for _, cmd := range batch.cmds {
			if err := cmd.Execute(bkt); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		d.logger.Error("Batch Write() failed",
			"err", err,
		)
	}

	return err
}

func (d *boltDBImpl) newIterator(start, end []byte, isForward bool) dbm.Iterator {
	iter := &boltDBIterator{
		db:        d,
		start:     start,
		end:       end,
		isForward: isForward,
	}

	// Note: This holds a read transaction for the lifetime of the iterator.
	//
	// If the iterator ends up being long lived, this can negatively impact
	// BoltDB's page level garbage collection.
	var err error
	iter.tx, err = d.db.Begin(false)
	if err != nil {
		d.logger.Error("newIterator: Begin() failed",
			"err", err,
		)
		panic(err)
	}

	bkt := iter.tx.Bucket(bktContents)
	cur := bkt.Cursor()

	var firstFn func() ([]byte, []byte)
	switch isForward {
	case true:
		iter.nextFn = cur.Next
		firstFn = cur.First
	case false:
		iter.nextFn = cur.Prev
		firstFn = cur.Last
	}

	// Seek to the first applicable key/value pair.
	k, v := firstFn()
	if k == nil {
		// Empty database, invalid iterator.
		return iter
	}

	k = fromBoltDBKey(k)
	iter.isValid = true // Assume valid, seeking will reset.
	if dbm.IsKeyInDomain(k, start, end, !isForward) {
		// First key happens to be in the domain.
		iter.current.key = k
		iter.current.value = append([]byte{}, v...)
		return iter
	}

	iter.Next()

	return iter
}

type boltDBIterator struct {
	db     *boltDBImpl
	tx     *bolt.Tx
	nextFn func() ([]byte, []byte)

	start, end []byte

	current struct {
		key, value []byte
	}

	isValid   bool
	isForward bool
}

func (iter *boltDBIterator) Domain() ([]byte, []byte) {
	return iter.start, iter.end
}

func (iter *boltDBIterator) Valid() bool {
	return iter.isValid
}

func (iter *boltDBIterator) Next() {
	if !iter.Valid() {
		panic("Next() with invalid iterator")
	}

	// Traverse the BoltDB cursor to find the next applicable key.
	for k, v := iter.nextFn(); k != nil; k, v = iter.nextFn() {
		k = fromBoltDBKey(k)
		if dbm.IsKeyInDomain(k, iter.start, iter.end, !iter.isForward) {
			iter.current.key = k
			iter.current.value = append([]byte{}, v...)
			return
		}
	}

	// Close() is idempotent, so do so the moment the iterator
	// is invalidated, to reduce the amount of time the read
	// transaction is held onto.
	iter.Close()
}

func (iter *boltDBIterator) Key() []byte {
	if !iter.Valid() {
		panic("Key() with invalid iterator")
	}

	return iter.current.key
}

func (iter *boltDBIterator) Value() []byte {
	if !iter.Valid() {
		panic("Value() with invalid iterator")
	}

	return iter.current.value
}

func (iter *boltDBIterator) Close() {
	if iter.tx != nil {
		if err := iter.tx.Rollback(); err != nil {
			iter.db.logger.Error("iterator: Rollback() failed",
				"err", err,
			)
			panic(err)
		}
		iter.tx = nil
	}
	iter.isValid = false
}

type batchCmd interface {
	Execute(bkt *bolt.Bucket) error
}

type batchCmdSet struct {
	key, value []byte
}

func (cmd *batchCmdSet) Execute(bkt *bolt.Bucket) error {
	return bkt.Put(cmd.key, cmd.value)
}

type batchCmdDelete struct {
	key []byte
}

func (cmd *batchCmdDelete) Execute(bkt *bolt.Bucket) error {
	return bkt.Delete(cmd.key)
}

type boltDBBatch struct {
	db   *boltDBImpl
	cmds []batchCmd
}

func (b *boltDBBatch) Set(key, value []byte) {
	b.cmds = append(b.cmds, &batchCmdSet{
		key:   toBoltDBKey(key),
		value: value,
	})
}

func (b *boltDBBatch) Delete(key []byte) {
	b.cmds = append(b.cmds, &batchCmdDelete{
		key: toBoltDBKey(key),
	})
}

func (b *boltDBBatch) Write() {
	if err := b.db.writeBatch(b); err != nil {
		panic(err)
	}
}

func (b *boltDBBatch) WriteSync() {
	b.Write()
	b.db.sync()
}

func toBoltDBKey(key []byte) []byte {
	// BoltDB doesn't allow zero-length keys, so make all keys at least
	// 1 byte long.
	ret := make([]byte, 1, 1+len(key))
	ret[0] = dbVersion
	ret = append(ret, key...)

	return ret
}

func fromBoltDBKey(key []byte) []byte {
	if len(key) < 1 {
		panic("BUG: zero-length key in BoltDB database")
	}
	if key[0] != dbVersion {
		panic("BUG: unknown key version byte")
	}

	ret := make([]byte, 0, len(key)-1)
	ret = append(ret, key[1:]...)

	return ret
}
