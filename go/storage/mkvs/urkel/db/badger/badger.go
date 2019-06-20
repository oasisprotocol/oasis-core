// Package badger provides a Badger-backed node database.
package badger

import (
	"github.com/dgraph-io/badger/v2"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

var (
	nodeKeyPrefix  = []byte{'N'}
	valueKeyPrefix = []byte{'V'}
)

// New creates a new BadgerDB-backed node database.
func New(opts badger.Options) (api.NodeDB, error) {
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
		return nil, api.ErrNodeNotFound
	default:
		d.logger.Error("failed to Get node from backing store",
			"err", err,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to Get node from backing store")
	}

	var node internal.Node
	if err = item.Value(func(val []byte) error {
		var vErr error
		node, vErr = internal.NodeUnmarshalBinary(val)
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

func (d *badgerNodeDB) NewBatch() api.Batch {
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

func (ba *badgerBatch) MaybeStartSubtree(subtree api.Subtree, depth uint8, subtreeRoot *internal.Pointer) api.Subtree {
	if subtree == nil {
		return &badgerSubtree{batch: ba}
	}
	return subtree
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

type badgerSubtree struct {
	batch *badgerBatch
}

func (s *badgerSubtree) PutNode(depth uint8, ptr *internal.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	switch n := ptr.Node.(type) {
	case *internal.InternalNode:
		if err = s.batch.bat.Set(append(nodeKeyPrefix, n.Hash[:]...), data); err != nil {
			return err
		}
	case *internal.LeafNode:
		if err = s.batch.bat.Set(append(valueKeyPrefix, n.Value.Hash[:]...), n.Value.Value); err != nil {
			return err
		}
		if err = s.batch.bat.Set(append(nodeKeyPrefix, n.Hash[:]...), data); err != nil {
			return err
		}
	}
	return nil
}

func (s *badgerSubtree) VisitCleanNode(depth uint8, ptr *internal.Pointer) error {
	return nil
}

func (s *badgerSubtree) Commit() error {
	return nil
}
