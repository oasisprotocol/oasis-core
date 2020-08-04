// Package badger implements a tendermint DB, backed by BadgerDB.
package badger

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"github.com/tendermint/tendermint/node"
	dbm "github.com/tendermint/tm-db"

	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "badger"

	dbVersion = 1
	dbSuffix  = ".badger.db"
)

var (
	baseLogger = logging.GetLogger("tendermint/db/badger")

	// DBProvider is a DBProvider to be used when initializing
	// a tendermint node.
	DBProvider node.DBProvider = badgerDBProvider

	dbVersionStart = []byte{dbVersion}
	dbVersionEnd   = []byte{dbVersion + 1}
)

func badgerDBProvider(ctx *node.DBContext) (dbm.DB, error) {
	// BadgerDB can handle dealing with the directory for us.
	return New(filepath.Join(ctx.Config.DBDir(), ctx.ID), false)
}

type badgerDBImpl struct {
	logger *logging.Logger

	db *badger.DB
	gc *cmnBadger.GCWorker

	closeOnce sync.Once
}

// New constructs a new tendermint DB, backed by a Badger database at
// the provided path.
//
// Note: This should only be used by tendermint, all other places
// that need a K/V store should favor using BadgerDB directly.
func New(fn string, noSuffix bool) (dbm.DB, error) {
	if !noSuffix && !strings.HasSuffix(fn, dbSuffix) {
		fn = fn + dbSuffix
	}

	logger := baseLogger.With("path", fn)

	opts := badger.DefaultOptions(fn) // This may benefit from LSMOnlyOptions.
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(logger))
	opts = opts.WithSyncWrites(false)
	// Allow value log truncation if required (this is needed to recover the
	// value log file which can get corrupted in crashes).
	opts = opts.WithTruncate(true)
	opts = opts.WithCompression(options.Snappy)
	// Reduce cache size to 64 MiB as the default is 1 GiB.
	opts = opts.WithMaxCacheSize(64 * 1024 * 1024)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("tendermint/db/badger: failed to open database: %w", err)
	}

	impl := &badgerDBImpl{
		logger: logger,
		db:     db,
		gc:     cmnBadger.NewGCWorker(logger, db),
	}

	return impl, nil
}

func (d *badgerDBImpl) Get(key []byte) ([]byte, error) {
	k := toDBKey(key)

	var value []byte
	err := d.db.View(func(tx *badger.Txn) error {
		item, txErr := tx.Get(k)
		switch txErr {
		case nil:
		case badger.ErrKeyNotFound:
			return nil
		default:
			return txErr
		}

		return item.Value(func(val []byte) error {
			value = append([]byte{}, val...)
			return nil
		})
	})
	if err != nil {
		d.logger.Error("Get failed",
			"err", err,
			"key", string(key),
		)
	}

	return value, err
}

func (d *badgerDBImpl) Has(key []byte) (bool, error) {
	k := toDBKey(key)

	var exists bool
	err := d.db.View(func(tx *badger.Txn) error {
		_, txErr := tx.Get(k)
		switch txErr {
		case nil:
			exists = true
		case badger.ErrKeyNotFound:
		default:
			return txErr
		}
		return nil
	})
	if err != nil {
		d.logger.Error("Has failed",
			"err", err,
			"key", string(key),
		)
	}

	return exists, err
}

func (d *badgerDBImpl) Set(key, value []byte) error {
	k := toDBKey(key)

	err := d.db.Update(func(tx *badger.Txn) error {
		return tx.Set(k, value)
	})
	if err != nil {
		d.logger.Error("Set failed",
			"err", err,
			"key", string(key),
		)
	}

	return nil
}

func (d *badgerDBImpl) SetSync(key, value []byte) error {
	err := d.Set(key, value)
	if err == nil {
		err = d.sync()
	}
	return err
}

func (d *badgerDBImpl) sync() error {
	err := d.db.Sync()
	if err != nil {
		d.logger.Error("Sync failed",
			"err", err,
		)
	}
	return err
}

func (d *badgerDBImpl) Delete(key []byte) error {
	k := toDBKey(key)

	err := d.db.Update(func(tx *badger.Txn) error {
		txErr := tx.Delete(k)
		switch txErr {
		case nil, badger.ErrKeyNotFound:
		default:
			return txErr
		}
		return nil
	})
	if err != nil {
		d.logger.Error("Delete failed",
			"err", err,
			"key", string(key),
		)
	}
	return err
}

func (d *badgerDBImpl) DeleteSync(key []byte) error {
	err := d.Delete(key)
	if err == nil {
		err = d.sync()
	}
	return err
}

func (d *badgerDBImpl) Iterator(start, end []byte) (dbm.Iterator, error) {
	return d.newIterator(start, end, true), nil
}

func (d *badgerDBImpl) ReverseIterator(start, end []byte) (dbm.Iterator, error) {
	return d.newIterator(start, end, false), nil
}

func (d *badgerDBImpl) Close() error {
	err := os.ErrClosed
	d.closeOnce.Do(func() {
		d.gc.Close()

		if err = d.db.Close(); err != nil {
			d.logger.Error("Close failed",
				"err", err,
			)
		}
	})

	return err
}

func (d *badgerDBImpl) NewBatch() dbm.Batch {
	return &badgerDBBatch{
		db: d,
	}
}

func (d *badgerDBImpl) Print() error {
	// There's better ways to dump a database...
	d.logger.Debug("Print() refusing to dump the database")

	return nil
}

func (d *badgerDBImpl) Stats() map[string]string {
	m := make(map[string]string)
	m["database.type"] = "Badger"

	lsm, vlog := d.db.Size()
	m["database.lsm_size"] = fmt.Sprintf("%v", lsm)
	m["database.vlog_size"] = fmt.Sprintf("%v", vlog)

	return m
}

func (d *badgerDBImpl) Size() (int64, error) {
	lsm, vlog := d.db.Size()
	return lsm + vlog, nil
}

func (d *badgerDBImpl) newIterator(start, end []byte, isForward bool) dbm.Iterator {
	opts := badger.DefaultIteratorOptions
	opts.Reverse = !isForward

	// While prefetching values should be a win, the iavl access patterns
	// result in out of control CPU usage.  Of note is a staggering 20% of
	// CPU being spent in `nodeDB.getPreviousVersion` under profiling.
	opts.PrefetchValues = false

	// TODO/perf:
	//  * opts.Prefix is likely worth setting, but maybe the tendermint
	//    semantics can't be implemented.
	opts.Prefix = dbVersionStart

	tx := d.db.NewTransaction(false)
	it := &badgerDBIterator{
		db:        d,
		tx:        tx,
		iter:      tx.NewIterator(opts),
		start:     start,
		end:       end,
		isForward: isForward,
	}

	if start == nil {
		it.dbStart = dbVersionStart
	} else {
		it.dbStart = toDBKey(start)
	}
	if end == nil {
		it.dbEnd = dbVersionEnd
	} else {
		it.dbEnd = toDBKey(end)
	}

	// Seek to the first applicable key/value pair.
	switch isForward {
	case true:
		it.iter.Seek(it.dbStart)
	case false:
		it.iter.Seek(it.dbEnd)
		if it.iter.Valid() {
			item := it.iter.Item()
			if bytes.Equal(it.dbEnd, item.Key()) {
				it.iter.Next()
			}
		}
	}

	return it
}

type badgerDBIterator struct {
	db   *badgerDBImpl
	tx   *badger.Txn
	iter *badger.Iterator

	start, end []byte
	// Version-prefixed fences for simple bounds checks.
	dbStart, dbEnd []byte
	isForward      bool
}

func (it *badgerDBIterator) Domain() ([]byte, []byte) {
	return it.start, it.end
}

func (it *badgerDBIterator) Valid() bool {
	if it.iter != nil && !it.iter.Valid() {
		return false
	}

	dbKey := it.iter.Item().Key()
	switch it.isForward {
	case true:
		if bytes.Compare(it.dbEnd, dbKey) <= 0 {
			return false
		}
	case false:
		if bytes.Compare(dbKey, it.dbStart) < 0 {
			return false
		}
	}

	return true
}

func (it *badgerDBIterator) Next() {
	if !it.Valid() {
		panic("Next with invalid iterator")
	}

	it.iter.Next()
}

func (it *badgerDBIterator) Key() []byte {
	if !it.Valid() {
		panic("Key with invalid iterator")
	}

	item := it.iter.Item()
	return fromDBKeyNoCopy(item.KeyCopy(nil))
}

func (it *badgerDBIterator) Value() []byte {
	if !it.Valid() {
		panic("Value with invalid iterator")
	}

	item := it.iter.Item()
	value, err := item.ValueCopy(nil)
	if err != nil {
		it.db.logger.Error("failed to retrieve/decompress iterator value",
			"err", err,
			"key", string(fromDBKeyNoCopy(item.KeyCopy(nil))),
		)
		panic(err)
	}
	return value
}

func (it *badgerDBIterator) Error() error {
	return nil
}

func (it *badgerDBIterator) Close() error {
	if it.iter != nil {
		it.iter.Close()
		it.tx.Discard()

		it.tx = nil
		it.iter = nil
	}
	return nil
}

type setDeleter interface {
	Set(k, v []byte) error
	Delete(k []byte) error
}

type batchCmd interface {
	Execute(setDeleter) error
	String() string
}

type setCmd struct {
	key, value []byte
}

func (cmd *setCmd) Execute(sd setDeleter) error {
	return sd.Set(cmd.key, cmd.value)
}

func (cmd *setCmd) String() string {
	return fmt.Sprintf("set(%v, [compressed])", string(fromDBKeyNoCopy(cmd.key)))
}

type deleteCmd struct {
	key []byte
}

func (cmd *deleteCmd) Execute(sd setDeleter) error {
	return sd.Delete(cmd.key)
}

func (cmd *deleteCmd) String() string {
	return fmt.Sprintf("delete(%v)", string(fromDBKeyNoCopy(cmd.key)))
}

type badgerDBBatch struct {
	db   *badgerDBImpl
	cmds []batchCmd
}

func (ba *badgerDBBatch) Set(key, value []byte) error {
	ba.cmds = append(ba.cmds, &setCmd{
		key:   toDBKey(key),
		value: append([]byte{}, value...),
	})
	return nil
}

func (ba *badgerDBBatch) Delete(key []byte) error {
	ba.cmds = append(ba.cmds, &deleteCmd{
		key: toDBKey(key),
	})
	return nil
}

func (ba *badgerDBBatch) Write() error {
	wb := ba.db.db.NewWriteBatch()
	defer wb.Cancel()

	for _, cmd := range ba.cmds {
		if err := cmd.Execute(wb); err != nil {
			ba.db.logger.Error("failed to execute command in WriteBatch",
				"err", err,
				"cmd", cmd,
			)
			return err
		}
	}

	if err := wb.Flush(); err != nil {
		ba.db.logger.Error("failed to flush WriteBatch",
			"err", err,
		)
		return err
	}

	ba.Close()

	return nil
}

func (ba *badgerDBBatch) WriteSync() error {
	tx := ba.db.db.NewTransaction(true)
	defer tx.Discard()

	for _, cmd := range ba.cmds {
		if err := cmd.Execute(tx); err != nil {
			ba.db.logger.Error("failed to execute command in Tx",
				"err", err,
				"cmd", cmd,
			)
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		ba.db.logger.Error("failed to commit Tx",
			"err", err,
		)
		return err
	}

	err := ba.db.sync()

	ba.Close()

	return err
}

func (ba *badgerDBBatch) Close() error {
	ba.db = nil
	ba.cmds = nil
	return nil
}

func toDBKey(key []byte) []byte {
	ret := make([]byte, 1, 1+len(key))
	ret[0] = dbVersion
	ret = append(ret, key...)

	return ret
}

func fromDBKeyNoCopy(key []byte) []byte {
	if len(key) < 1 {
		panic("BUG: zero-length key in Badger database")
	}
	if key[0] != dbVersion {
		panic("BUG: unknown key version byte")
	}

	return key[1:]
}
