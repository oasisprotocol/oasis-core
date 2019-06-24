package db

import (
	"github.com/dgraph-io/badger/v2"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

// NewBadgerNodeDB creates a new BadgerDB-backed node database.
func NewBadgerNodeDB(opts badger.Options) (NodeDB, error) {
	db := &badgerNodeDB{
		logger: logging.GetLogger("urkel/db/badger"),
	}

	var err error
	if db.db, err = badger.Open(opts); err != nil {
		return nil, errors.Wrap(err, "urkel/db/badger: failed to open database")
	}

	return db, nil
}

type badgerNodeDB struct {
	logger *logging.Logger

	db *badger.DB
}

func (d *badgerNodeDB) GetNode(root hash.Hash, ptr *internal.Pointer) (internal.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/badger: attempted to get invalid pointer from node database")
	}

	tx := d.db.NewTransaction(false)
	defer tx.Discard()
	item, err := tx.Get(append(nodeKeyPrefix, ptr.Hash[:]...))
	switch err {
	case nil:
	case badger.ErrKeyNotFound:
		return nil, ErrNodeNotFound
	default:
		d.logger.Error("failed to Get node from backing store",
			"err", err,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to Get node from backing store")
	}

	var node internal.Node
	if err = item.Value(func(val []byte) error {
		var vErr error
		node, vErr = NodeUnmarshalBinary(val)
		return vErr
	}); err != nil {
		d.logger.Error("failed to unmarshal node",
			"err", err,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to unmarshal node")
	}

	return node, nil
}

func (d *badgerNodeDB) GetValue(id hash.Hash) ([]byte, error) {
	tx := d.db.NewTransaction(false)
	defer tx.Discard()
	item, err := tx.Get(append(valueKeyPrefix, id[:]...))
	if err != nil {
		d.logger.Error("failed to Get value from backing store",
			"err", err,
			"id", id,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to Get value from backing store")
	}

	v, err := item.ValueCopy(nil)
	if err != nil {
		d.logger.Error("failed to copy value from value log",
			"err", err,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to copy value from value log")
	}

	return v, nil
}

func (d *badgerNodeDB) NewBatch() Batch {
	// WARNING: There is a maximum batch size and maximum batch entry count.
	// Both of these things are derived from the MaxTableSize option.
	//
	// The size limit also applies to normal transactions, so the "right"
	// thing to do would be to either crank up MaxTableSize or maybe split
	// the transaction out.

	return &badgerBatch{
		bat: d.db.NewWriteBatch(),
	}
}

func (d *badgerNodeDB) Close() {
	if err := d.db.Close(); err != nil {
		d.logger.Error("close returned error",
			"err", err,
		)
	}
}

type badgerBatch struct {
	bat *badger.WriteBatch
}

func (ba *badgerBatch) PutNode(ptr *internal.Pointer) error {
	if ptr == nil || ptr.Node == nil {
		panic("urkel/db/badger: attempted to put invalid pointer to node database")
	}

	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "urkel/db/badger: failed to marshal node")
	}

	hash := ptr.Node.GetHash()
	return ba.bat.Set(append(nodeKeyPrefix, hash[:]...), data)
}

func (ba *badgerBatch) RemoveNode(ptr *internal.Pointer) error {
	if ptr == nil || ptr.Node == nil {
		panic("urkel/db/badger: attempted to remove invalid node pointer from node database")
	}

	hash := ptr.Node.GetHash()
	return ba.bat.Delete(append(nodeKeyPrefix, hash[:]...))
}

func (ba *badgerBatch) PutValue(value []byte) error {
	var id hash.Hash
	id.FromBytes(value)

	return ba.bat.Set(append(valueKeyPrefix, id[:]...), value)
}

func (ba *badgerBatch) RemoveValue(id hash.Hash) error {
	return ba.bat.Delete(append(valueKeyPrefix, id[:]...))
}

func (ba *badgerBatch) Commit(root hash.Hash) error {
	if err := ba.bat.Flush(); err != nil {
		return err
	}

	return nil
}

func (ba *badgerBatch) Reset() {
	ba.bat.Cancel()
}
