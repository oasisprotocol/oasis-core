// Package badger implements a tendermint DB, backed by BadgerDB.
package badger

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dgraph-io/badger"
	"github.com/golang/snappy"
	"github.com/pkg/errors"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/node"

	"github.com/oasislabs/ekiden/go/common/logging"
	ekbadger "github.com/oasislabs/ekiden/go/storage/badger"
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
)

func badgerDBProvider(ctx *node.DBContext) (dbm.DB, error) {
	// BadgerDB can handle dealing with the directory for us.
	return New(filepath.Join(ctx.Config.DBDir(), ctx.ID), false)
}

type badgerDBImpl struct {
	logger *logging.Logger

	db *badger.DB
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
	opts = opts.WithLogger(ekbadger.NewLogAdapter(logger))
	opts = opts.WithSyncWrites(false)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint/db/badger: failed to open database")
	}

	return &badgerDBImpl{
		logger: logger,
		db:     db,
	}, nil
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
			value, txErr = snappy.Decode(nil, val)
			return txErr
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
	valueCompressed := snappy.Encode(nil, value)

	if err := d.db.Update(func(tx *badger.Txn) error {
		return tx.Set(k, valueCompressed)
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
	if err := d.db.Close(); err != nil {
		d.logger.Error("Close failed",
			"err", err,
		)
		// Log but ignore the error.
	}
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

func (d *badgerDBImpl) newIterator(start, end []byte, isForward bool) dbm.Iterator {
	opts := badger.DefaultIteratorOptions
	opts.Reverse = !isForward
	// TODO/perf:
	//  * opts.Prefix is likely worth setting, but maybe the tendermint
	//    semantics can't be implemented.
	//  * Depending on if iter.Value() is called frequently or not,
	//    mess with the pre-fetch settings.

	tx := d.db.NewTransaction(false)
	it := &badgerDBIterator{
		db:    d,
		tx:    tx,
		iter:  tx.NewIterator(opts),
		start: start,
		end:   end,
	}

	// Seek to the first applicable key/value pair.
	switch isForward {
	case true:
		if start == nil {
			it.iter.Rewind()
		} else {
			it.iter.Seek(toDBKey(start))
		}
	case false:
		if end == nil {
			it.iter.Rewind()
		} else {
			it.iter.Seek(toDBKey(end))
			if it.iter.Valid() {
				item := it.iter.Item()
				if bytes.Compare(end, fromDBKeyNoCopy(item.Key())) <= 0 {
					it.iter.Next()
				}
			} else {
				it.iter.Rewind()
			}
		}
	}

	// Well, iterator starts off empty.
	if !it.iter.Valid() {
		it.Close()
		return it
	}

	// There is a k/v pair at the start.
	it.isValid = true
	item := it.iter.Item()
	k := fromDBKeyNoCopy(item.KeyCopy(nil))
	if dbm.IsKeyInDomain(k, start, end) {
		// First key is in the domain.
		it.current.item = item
		it.current.key = k
		return it
	}

	// First key isn't in the domain, seek till we are in the appropriate
	// range.
	it.Next()

	return it
}

type badgerDBIterator struct {
	db   *badgerDBImpl
	tx   *badger.Txn
	iter *badger.Iterator

	current struct {
		item       *badger.Item
		key, value []byte
	}

	start, end []byte
	isValid    bool
}

func (it *badgerDBIterator) Domain() ([]byte, []byte) {
	return it.start, it.end
}

func (it *badgerDBIterator) Valid() bool {
	// Might as well be sure.
	if it.iter != nil && !it.iter.Valid() {
		it.Close()
	}

	return it.isValid
}

func (it *badgerDBIterator) Next() {
	if !it.Valid() {
		panic("Next with invalid iterator")
	}

	for {
		it.iter.Next()
		if !it.iter.Valid() {
			break
		}

		item := it.iter.Item()
		k := fromDBKeyNoCopy(item.KeyCopy(nil))
		if dbm.IsKeyInDomain(k, it.start, it.end) {
			it.current.item = item
			it.current.key = k
			it.current.value = nil // Decompress done on access.
			return
		}
	}

	it.Close()
}

func (it *badgerDBIterator) Key() []byte {
	if !it.Valid() {
		panic("Key with invalid iterator")
	}

	// TODO/perf: Technically don't need a copy for safety.
	return append([]byte{}, it.current.key...)
}

func (it *badgerDBIterator) Value() []byte {
	if !it.Valid() {
		panic("Value with invalid iterator")
	}

	if it.current.value == nil {
		if err := it.current.item.Value(func(val []byte) error {
			var decErr error
			it.current.value, decErr = snappy.Decode(nil, val)
			return decErr
		}); err != nil {
			it.db.logger.Error("failed to retrieve/decompress iterator value",
				"err", err,
				"key", string(it.current.key),
			)
			panic(err)
		}
	}

	// TODO/perf: Technically don't need a copy for safety.
	return append([]byte{}, it.current.value...)
}

func (it *badgerDBIterator) Close() {
	if it.iter != nil {
		it.iter.Close()
		it.tx.Discard()

		it.tx = nil
		it.iter = nil
		it.current.item = nil
	}
	it.isValid = false
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
		value: snappy.Encode(nil, value),
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
