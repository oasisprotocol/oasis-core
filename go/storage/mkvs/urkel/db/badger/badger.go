// Package badger provides a Badger-backed node database.
package badger

import (
	"context"
	"sync"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

const (
	gcInterval     = 5 * time.Minute
	gcDiscardRatio = 0.5
)

var (
	nodeKeyPrefix     = []byte{'N'}
	writeLogKeyPrefix = []byte{'L'}
)

func makeWriteLogKey(startRoot node.Root, endRoot node.Root) []byte {
	return append(append(writeLogKeyPrefix, startRoot.Hash[:]...), endRoot.Hash[:]...)
}

// New creates a new BadgerDB-backed node database.
func New(opts badger.Options) (api.NodeDB, error) {
	db := &badgerNodeDB{
		logger:   logging.GetLogger("urkel/db/badger"),
		closeCh:  make(chan struct{}),
		closedCh: make(chan struct{}),
	}

	var err error
	if db.db, err = badger.Open(opts); err != nil {
		return nil, errors.Wrap(err, "urkel/db/badger: failed to open database")
	}
	go db.gcWorker()

	return db, nil
}

type badgerNodeDB struct {
	logger *logging.Logger

	db *badger.DB

	closeOnce sync.Once
	closeCh   chan struct{}
	closedCh  chan struct{}
}

func (d *badgerNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
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

	var n node.Node
	if err = item.Value(func(val []byte) error {
		var vErr error
		n, vErr = node.UnmarshalBinary(val)
		return vErr
	}); err != nil {
		d.logger.Error("failed to unmarshal node",
			"err", err,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to unmarshal node")
	}

	return n, nil
}

func (d *badgerNodeDB) GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (api.WriteLogIterator, error) {
	if !endRoot.Follows(&startRoot) {
		return nil, errors.New("urkel/db/badger: end root must follow start root")
	}

	tx := d.db.NewTransaction(false)
	defer tx.Discard()
	item, err := tx.Get(makeWriteLogKey(startRoot, endRoot))
	if err != nil {
		d.logger.Error("failed to Get write log from backing store",
			"err", err,
			"start_root", startRoot,
			"end_root", endRoot,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to Get write log from backing store")
	}
	bytes, err := item.ValueCopy(nil)
	if err != nil {
		d.logger.Error("failed to copy bytes from write log value",
			"err", err,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to copy bytes from write log value")
	}

	var dbLog api.HashedDBWriteLog
	if err := cbor.Unmarshal(bytes, &dbLog); err != nil {
		d.logger.Error("failed to unmarshal write log",
			"err", err,
		)
		return nil, errors.Wrap(err, "urkel/db/badger: failed to unmarshal write log")
	}

	return api.ReviveHashedDBWriteLog(ctx, dbLog, func(h hash.Hash) (*node.LeafNode, error) {
		leaf, err := d.GetNode(endRoot, &node.Pointer{Hash: h, Clean: true})
		if err != nil {
			return nil, err
		}
		return leaf.(*node.LeafNode), nil
	})
}

func (d *badgerNodeDB) HasRoot(root node.Root) bool {
	_, err := d.GetNode(root, &node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	})
	return err != api.ErrNodeNotFound
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
	d.closeOnce.Do(func() {
		close(d.closeCh)
		<-d.closedCh

		if err := d.db.Close(); err != nil {
			d.logger.Error("close returned error",
				"err", err,
			)
		}
	})
}

func (d *badgerNodeDB) gcWorker() {
	defer close(d.closedCh)

	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()

	doGC := func() error {
		for {
			if err := d.db.RunValueLogGC(gcDiscardRatio); err != nil {
				return err
			}
		}
	}

	for {
		select {
		case <-d.closeCh:
			return
		case <-ticker.C:
		}

		// Run the value log GC.
		err := doGC()
		switch err {
		case nil, badger.ErrNoRewrite:
		default:
			d.logger.Error("failed to GC value log",
				"err", err,
			)
		}
	}
}

type badgerBatch struct {
	api.BaseBatch

	bat *badger.WriteBatch
}

func (ba *badgerBatch) MaybeStartSubtree(subtree api.Subtree, depth uint8, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &badgerSubtree{batch: ba}
	}
	return subtree
}

func (ba *badgerBatch) PutWriteLog(
	startRoot node.Root,
	endRoot node.Root,
	writeLog writelog.WriteLog,
	annotations writelog.WriteLogAnnotations,
) error {
	if !endRoot.Follows(&startRoot) {
		return errors.New("urkel/db/badger: end root must follow start root")
	}

	log := api.MakeHashedDBWriteLog(writeLog, annotations)
	bytes := cbor.Marshal(log)
	if err := ba.bat.Set(makeWriteLogKey(startRoot, endRoot), bytes); err != nil {
		return errors.Wrap(err, "urkel/db/badger: set returned error")
	}
	return nil
}

func (ba *badgerBatch) Commit(root node.Root) error {
	if err := ba.bat.Flush(); err != nil {
		return err
	}

	return ba.BaseBatch.Commit(root)
}

func (ba *badgerBatch) Reset() {
	ba.bat.Cancel()
}

type badgerSubtree struct {
	batch *badgerBatch
}

func (s *badgerSubtree) PutNode(depth uint8, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	h := ptr.Node.GetHash()
	if err = s.batch.bat.Set(append(nodeKeyPrefix, h[:]...), data); err != nil {
		return err
	}
	return nil
}

func (s *badgerSubtree) VisitCleanNode(depth uint8, ptr *node.Pointer) error {
	return nil
}

func (s *badgerSubtree) Commit() error {
	return nil
}
