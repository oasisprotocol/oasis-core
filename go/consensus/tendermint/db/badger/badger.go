// Package badger implements a tendermint DB, backed by BadgerDB.
package badger

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/node"
	dbm "github.com/tendermint/tm-db"

	cmnBadger "github.com/oasislabs/oasis-core/go/common/badger"
	"github.com/oasislabs/oasis-core/go/common/logging"
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
		return nil, errors.Wrap(err, "tendermint/db/badger: failed to open database")
	}

	impl := &badgerDBImpl{
		logger: logger,
		db:     db,
		gc:     cmnBadger.NewGCWorker(logger, db),
	}

	return impl, nil
}

func (d *badgerDBImpl) Get(key []byte) []byte {
	k := toDBKey(key)

	var value []byte
	if err := d.db.View(func(tx *badger.Txn) error {
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
	}); err != nil {
		d.logger.Error("Get failed",
			"err", err,
			"key", string(key),
		)
		panic(err)
	}

	return value
}

func (d *badgerDBImpl) Has(key []byte) bool {
	k := toDBKey(key)

	var exists bool
	if err := d.db.View(func(tx *badger.Txn) error {
		_, txErr := tx.Get(k)
		switch txErr {
		case nil:
			exists = true
		case badger.ErrKeyNotFound:
		default:
			return txErr
		}
		return nil
	}); err != nil {
		d.logger.Error("Has failed",
			"err", err,
			"key", string(key),
		)
		panic(err)
	}

	return exists
}

func (d *badgerDBImpl) Set(key, value []byte) {
	k := toDBKey(key)

	if err := d.db.Update(func(tx *badger.Txn) error {
		return tx.Set(k, value)
	}); err != nil {
		d.logger.Error("Set failed",
			"err", err,
			"key", string(key),
		)
		panic(err)
	}
}

func (d *badgerDBImpl) SetSync(key, value []byte) {
	d.Set(key, value)
	d.sync()
}

func (d *badgerDBImpl) sync() {
	if err := d.db.Sync(); err != nil {
		d.logger.Error("Sync failed",
			"err", err,
		)
		panic(err)
	}
}

func (d *badgerDBImpl) Delete(key []byte) {
	k := toDBKey(key)

	if err := d.db.Update(func(tx *badger.Txn) error {
		txErr := tx.Delete(k)
		switch txErr {
		case nil, badger.ErrKeyNotFound:
		default:
			return txErr
		}
		return nil
	}); err != nil {
		d.logger.Error("Delete failed",
			"err", err,
			"key", string(key),
		)
		panic(err)
	}
}

func (d *badgerDBImpl) DeleteSync(key []byte) {
	d.Delete(key)
	d.sync()
}

func (d *badgerDBImpl) Iterator(start, end []byte) dbm.Iterator {
	return d.newIterator(start, end, true)
}

func (d *badgerDBImpl) ReverseIterator(start, end []byte) dbm.Iterator {
	return d.newIterator(start, end, false)
}

func (d *badgerDBImpl) Close() {
	d.closeOnce.Do(func() {
		d.gc.Close()

		if err := d.db.Close(); err != nil {
			d.logger.Error("Close failed",
				"err", err,
			)
			// Log but ignore the error.
		}
	})
}

func (d *badgerDBImpl) NewBatch() dbm.Batch {
	return &badgerDBBatch{
		db: d,
	}
}

func (d *badgerDBImpl) Print() {
	// There's better ways to dump a database...
	d.logger.Debug("Print() refusing to dump the database")
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

func (it *badgerDBIterator) Close() {
	if it.iter != nil {
		it.iter.Close()
		it.tx.Discard()

		it.tx = nil
		it.iter = nil
	}
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

func (ba *badgerDBBatch) Set(key, value []byte) {
	ba.cmds = append(ba.cmds, &setCmd{
		key:   toDBKey(key),
		value: append([]byte{}, value...),
	})
}

func (ba *badgerDBBatch) Delete(key []byte) {
	ba.cmds = append(ba.cmds, &deleteCmd{
		key: toDBKey(key),
	})
}

func (ba *badgerDBBatch) Write() {
	wb := ba.db.db.NewWriteBatch()
	defer wb.Cancel()

	for _, cmd := range ba.cmds {
		if err := cmd.Execute(wb); err != nil {
			ba.db.logger.Error("failed to execute command in WriteBatch",
				"err", err,
				"cmd", cmd,
			)
			panic(err)
		}
	}

	if err := wb.Flush(); err != nil {
		ba.db.logger.Error("failed to flush WriteBatch",
			"err", err,
		)
		panic(err)
	}
}

func (ba *badgerDBBatch) WriteSync() {
	tx := ba.db.db.NewTransaction(true)
	defer tx.Discard()

	for _, cmd := range ba.cmds {
		if err := cmd.Execute(tx); err != nil {
			ba.db.logger.Error("failed to execute command in Tx",
				"err", err,
				"cmd", cmd,
			)
			panic(err)
		}
	}

	if err := tx.Commit(); err != nil {
		ba.db.logger.Error("failed to commit Tx",
			"err", err,
		)
		panic(err)
	}

	ba.db.sync()
}

func (ba *badgerDBBatch) Close() {
	ba.db = nil
	ba.cmds = nil
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
