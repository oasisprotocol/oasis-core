// Package badger provides a Badger-backed node database.
package badger

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/keyformat"
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
	_ api.NodeDB = (*badgerNodeDB)(nil)

	// TODO: Storing the full namespace with each node seems quite inefficient.

	// nodeKeyFmt is the key format for nodes (namespace, node hash).
	//
	// Value is serialized node.
	nodeKeyFmt = keyformat.New('N', &common.Namespace{}, &hash.Hash{})
	// writeLogKeyFmt is the key format for write logs (namespace, round,
	// new root, old root).
	//
	// Value is CBOR-serialized write log.
	writeLogKeyFmt = keyformat.New('L', &common.Namespace{}, uint64(0), &hash.Hash{}, &hash.Hash{})
	// rootLinkKeyFmt is the key format for the root links (namespace, round,
	// root).
	//
	// Value is next root hash.
	rootLinkKeyFmt = keyformat.New('M', &common.Namespace{}, uint64(0), &hash.Hash{})
	// rootGcUpdatesKeyFmt is the key format for the pending garbage collection
	// index updates that need to be applied only in case the given root is among
	// the finalized roots. The key format is (namespace, round, root).
	//
	// Value is CBOR-serialized list of updates for garbage collection index.
	rootGcUpdatesKeyFmt = keyformat.New('I', &common.Namespace{}, uint64(0), &hash.Hash{})
	// rootAddedNodesKeyFmt is the key format for the pending added nodes for the
	// given root that need to be removed only in case the given root is not among
	// the finalized roots. They key format is (namespace, round, root).
	//
	// Value is CBOR-serialized list of node hashes.
	rootAddedNodesKeyFmt = keyformat.New('J', &common.Namespace{}, uint64(0), &hash.Hash{})
	// gcIndexKeyFmt is the key format for the garbage collection index
	// (namespace, end round, start round, node hash).
	//
	// Value is empty.
	gcIndexKeyFmt = keyformat.New('G', &common.Namespace{}, uint64(0), uint64(0), &hash.Hash{})
	// finalizedKeyFmt is the key format for the last finalized round number.
	//
	// Value is the last finalized round number.
	finalizedKeyFmt = keyformat.New('F', &common.Namespace{})
)

// rootGcIndexUpdate is an element of the rootGcUpdates list.
type rootGcUpdate struct {
	_struct struct{} `codec:",toarray"` // nolint

	EndRound   uint64
	StartRound uint64
	Node       hash.Hash
}

// rootGcIndexUpdates is the value of the rootGcUpdates keys.
type rootGcUpdates []rootGcUpdate

// rootAddedNodes is the value of the rootAddedNodes keys.
type rootAddedNodes []hash.Hash

type metadata struct {
	sync.RWMutex

	lastFinalizedRound map[common.Namespace]uint64
}

func (m *metadata) getLastFinalizedRound(ns common.Namespace) (uint64, bool) {
	m.RLock()
	defer m.RUnlock()

	round, ok := m.lastFinalizedRound[ns]
	return round, ok
}

func (m *metadata) setLastFinalizedRound(ns common.Namespace, round uint64) {
	m.Lock()
	defer m.Unlock()

	if m.lastFinalizedRound == nil {
		m.lastFinalizedRound = make(map[common.Namespace]uint64)
	}
	m.lastFinalizedRound[ns] = round
}

// New creates a new BadgerDB-backed node database.
func New(cfg *api.Config) (api.NodeDB, error) {
	db := &badgerNodeDB{
		logger:   logging.GetLogger("urkel/db/badger"),
		closeCh:  make(chan struct{}),
		closedCh: make(chan struct{}),
	}
	db.CheckpointableDB = api.NewCheckpointableDB(db)

	opts := badger.DefaultOptions(cfg.DB)
	opts = opts.WithLogger(NewLogAdapter(db.logger))
	opts = opts.WithSyncWrites(!cfg.DebugNoFsync)

	var err error
	if db.db, err = badger.Open(opts); err != nil {
		return nil, errors.Wrap(err, "urkel/db/badger: failed to open database")
	}

	// Load database metadata.
	if err = db.load(); err != nil {
		_ = db.db.Close()
		return nil, errors.Wrap(err, "urkel/db/badger: failed to load metadata")
	}

	go db.gcWorker()

	return db, nil
}

type badgerNodeDB struct {
	api.CheckpointableDB

	logger *logging.Logger

	db   *badger.DB
	meta metadata

	closeOnce sync.Once
	closeCh   chan struct{}
	closedCh  chan struct{}
}

func (d *badgerNodeDB) load() error {
	d.meta.Lock()
	defer d.meta.Unlock()

	return d.db.View(func(tx *badger.Txn) error {
		// Load finalized rounds.
		it := tx.NewIterator(badger.IteratorOptions{Prefix: finalizedKeyFmt.Encode()})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			var decNs common.Namespace

			if !finalizedKeyFmt.Decode(item.Key(), &decNs) {
				// This should not happen as the Badger iterator should take care of it.
				panic("urkel/db/badger: bad iterator")
			}

			var lastFinalizedRound uint64
			err := item.Value(func(data []byte) error {
				return cbor.Unmarshal(data, &lastFinalizedRound)
			})
			if err != nil {
				return err
			}

			d.meta.lastFinalizedRound[decNs] = lastFinalizedRound
		}

		return nil
	})
}

func (d *badgerNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/badger: attempted to get invalid pointer from node database")
	}

	tx := d.db.NewTransaction(false)
	defer tx.Discard()
	item, err := tx.Get(nodeKeyFmt.Encode(&root.Namespace, &ptr.Hash))
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

func (d *badgerNodeDB) GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (writelog.Iterator, error) {
	if !endRoot.Follows(&startRoot) {
		return nil, api.ErrRootMustFollowOld
	}

	tx := d.db.NewTransaction(false)
	defer tx.Discard()
	key := writeLogKeyFmt.Encode(&endRoot.Namespace, endRoot.Round, &endRoot.Hash, &startRoot.Hash)
	item, err := tx.Get(key)
	if err != nil {
		d.logger.Error("failed to Get write log from backing store",
			"err", err,
			"old_root", startRoot,
			"new_root", endRoot,
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
	// An empty root is always implicitly present.
	if root.Hash.IsEmpty() {
		return true
	}

	err := d.db.View(func(tx *badger.Txn) error {
		_, err := tx.Get(rootLinkKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash))
		return err
	})
	switch err {
	case nil:
		return true
	case badger.ErrKeyNotFound:
		return false
	default:
		panic(err)
	}
}

func (d *badgerNodeDB) Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error { // nolint: gocyclo
	// We don't need to put the operations into a write transaction as the
	// content of the node database is based on immutable keys, so multiple
	// concurrent prunes cannot cause corruption.
	batch := d.db.NewWriteBatch()
	defer batch.Cancel()
	tx := d.db.NewTransaction(false)
	defer tx.Discard()

	// Make sure that the previous round has been finalized.
	lastFinalizedRound, exists := d.meta.getLastFinalizedRound(namespace)
	if round > 0 && (!exists || lastFinalizedRound < (round-1)) {
		return api.ErrNotFinalized
	}
	// Make sure that this round has not yet been finalized.
	if exists && round <= lastFinalizedRound {
		return api.ErrAlreadyFinalized
	}

	// Determine a set of finalized roots. Finalization is transitive, so if
	// a parent root is finalized the child should be consider finalized too.
	finalizedRoots := make(map[hash.Hash]bool)
	for _, rootHash := range roots {
		finalizedRoots[rootHash] = true
	}

	for updated := true; updated; {
		updated = false

		prefix := rootLinkKeyFmt.Encode(&namespace, round)
		it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			// If next root hash is among the finalized roots, add this root as well.
			var decNs common.Namespace
			var decRound uint64
			var rootHash hash.Hash

			if !rootLinkKeyFmt.Decode(item.Key(), &decNs, &decRound, &rootHash) {
				// This should not happen as the Badger iterator should take care of it.
				panic("urkel/db/badger: bad iterator")
			}

			if item.ValueSize() > 0 {
				var nextRoot hash.Hash
				err := item.Value(func(data []byte) error {
					return nextRoot.UnmarshalBinary(data)
				})
				if err != nil {
					panic("urkel/db/badger: corrupted root link index")
				}

				if !finalizedRoots[rootHash] && finalizedRoots[nextRoot] {
					finalizedRoots[rootHash] = true
					updated = true
				}
			}
		}
	}

	// Go through all roots and either commit GC updates or prune them based on
	// whether they are included in the finalized roots or not.
	prefix := rootLinkKeyFmt.Encode(&namespace, round)
	it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	maybeLoneNodes := make(map[hash.Hash]bool)
	notLoneNodes := make(map[hash.Hash]bool)

	for it.Rewind(); it.Valid(); it.Next() {
		var decNs common.Namespace
		var decRound uint64
		var rootHash hash.Hash

		if !rootLinkKeyFmt.Decode(it.Item().Key(), &decNs, &decRound, &rootHash) {
			// This should not happen as the Badger iterator should take care of it.
			panic("urkel/db/badger: bad iterator")
		}

		rootGcUpdatesKey := rootGcUpdatesKeyFmt.Encode(&namespace, round, &rootHash)
		rootAddedNodesKey := rootAddedNodesKeyFmt.Encode(&namespace, round, &rootHash)

		// Load hashes of nodes added during this round for this root.
		item, err := tx.Get(rootAddedNodesKey)
		if err != nil {
			panic("urkel/db/badger: corrupted root added nodes index")
		}

		var addedNodes rootAddedNodes
		err = item.Value(func(data []byte) error {
			return cbor.Unmarshal(data, &addedNodes)
		})
		if err != nil {
			panic("urkel/db/badger: corrupted root added nodes index")
		}

		if finalizedRoots[rootHash] {
			// Commit garbage collection index updates for any finalized roots.
			item, err = tx.Get(rootGcUpdatesKey)
			if err != nil {
				panic("urkel/db/badger: corrupted root gc updates index")
			}

			var gcUpdates rootGcUpdates
			err = item.Value(func(data []byte) error {
				return cbor.Unmarshal(data, &gcUpdates)
			})
			if err != nil {
				panic("urkel/db/badger: corrupted root gc updates index")
			}

			for _, u := range gcUpdates {
				key := gcIndexKeyFmt.Encode(&namespace, u.EndRound, u.StartRound, &u.Node)
				if err = batch.Set(key, []byte("")); err != nil {
					return err
				}
			}

			// Make sure not to remove any nodes shared with finalized roots.
			for _, h := range addedNodes {
				notLoneNodes[h] = true
			}
		} else {
			// Remove any non-finalized roots. It is safe to remove these nodes
			// as they can never be resurrected due to the round being part of the
			// node hash as long as we make sure that these nodes are not shared
			// with any finalized roots added in the same round.
			for _, h := range addedNodes {
				maybeLoneNodes[h] = true
			}
			if err = batch.Delete(it.Item().KeyCopy(nil)); err != nil {
				return err
			}
		}

		// GC updates no longer needed after finalization.
		if err = batch.Delete(rootGcUpdatesKey); err != nil {
			return err
		}
		// Set of added nodes no longer needed after finalization.
		if err = batch.Delete(rootAddedNodesKey); err != nil {
			return err
		}
	}

	// Clean any lone nodes.
	for h := range maybeLoneNodes {
		if notLoneNodes[h] {
			continue
		}

		key := nodeKeyFmt.Encode(&namespace, &h)
		if err := batch.Delete(key); err != nil {
			return err
		}
	}

	// Update last finalized round. This is done at the end as Badger may
	// split the batch into multiple transactions.
	if err := batch.Set(finalizedKeyFmt.Encode(&namespace), cbor.Marshal(round)); err != nil {
		return err
	}

	// Commit batch.
	if err := batch.Flush(); err != nil {
		return err
	}

	// Update cached last finalized round.
	d.meta.setLastFinalizedRound(namespace, round)

	return nil
}

func (d *badgerNodeDB) Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error) {
	// We don't need to put the operations into a write transaction as the
	// content of the node database is based on immutable keys, so multiple
	// concurrent prunes cannot cause corruption.
	batch := d.db.NewWriteBatch()
	defer batch.Cancel()
	tx := d.db.NewTransaction(false)
	defer tx.Discard()

	// Make sure that the round that we try to prune has been finalized.
	lastFinalizedRound, exists := d.meta.getLastFinalizedRound(namespace)
	if !exists || lastFinalizedRound < round {
		return 0, api.ErrNotFinalized
	}

	prevRound, err := getPreviousRound(tx, namespace, round)
	if err != nil {
		return 0, err
	}

	pruneHashes := make(map[hash.Hash]bool)

	// Iterate over all lifetimes that end in the passed round.
	prefix := gcIndexKeyFmt.Encode(&namespace, round)
	it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		var decNs common.Namespace
		var endRound uint64
		var startRound uint64
		var h hash.Hash

		if !gcIndexKeyFmt.Decode(it.Item().Key(), &decNs, &endRound, &startRound, &h) {
			// This should not happen as the Badger iterator should take care of it.
			panic("urkel/db/badger: bad iterator")
		}

		if err = batch.Delete(it.Item().KeyCopy(nil)); err != nil {
			return 0, err
		}

		if startRound > prevRound || startRound == endRound {
			// Either start round is after the previous round or the node starts and
			// terminates in the same round. Prune the node(s).
			pruneHashes[h] = true
		} else {
			// Since the current round is being pruned, the lifetime ends at the
			// previous round.
			if err = batch.Set(gcIndexKeyFmt.Encode(&decNs, prevRound, startRound, &h), []byte("")); err != nil {
				return 0, err
			}
		}
	}

	// Prune all roots in round.
	prefix = rootLinkKeyFmt.Encode(&namespace, round)
	it = tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		item := it.Item()

		// Prune lone roots (e.g., roots that start in the pruned round and don't
		// have any derived roots in following rounds).
		if item.ValueSize() == 0 {
			var decNs common.Namespace
			var decRound uint64
			var rootHash hash.Hash

			if !rootLinkKeyFmt.Decode(item.Key(), &decNs, &decRound, &rootHash) {
				// This should not happen as the LevelDB iterator should take care of it.
				panic("urkel/db/badger: bad iterator")
			}

			// Traverse the root and prune all items created in this round.
			root := node.Root{Namespace: namespace, Round: round, Hash: rootHash}
			err = api.Visit(ctx, d, root, func(ctx context.Context, n node.Node) bool {
				if n.GetCreatedRound() == round {
					pruneHashes[n.GetHash()] = true
				}
				return true
			})
			if err != nil {
				return 0, err
			}
		}

		if err = batch.Delete(item.KeyCopy(nil)); err != nil {
			return 0, err
		}
	}

	// Prune all write logs in round.
	prefix = writeLogKeyFmt.Encode(&namespace, round)
	it = tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		if err = batch.Delete(it.Item().KeyCopy(nil)); err != nil {
			return 0, err
		}
	}

	// Prune all collected hashes.
	var pruned int
	for h := range pruneHashes {
		if err = batch.Delete(nodeKeyFmt.Encode(&namespace, &h)); err != nil {
			return 0, err
		}
		pruned++
	}

	// Commit batch.
	if err := batch.Flush(); err != nil {
		return 0, err
	}

	return pruned, nil
}

func (d *badgerNodeDB) NewBatch(namespace common.Namespace, round uint64, oldRoot node.Root) api.Batch {
	// WARNING: There is a maximum batch size and maximum batch entry count.
	// Both of these things are derived from the MaxTableSize option.
	//
	// The size limit also applies to normal transactions, so the "right"
	// thing to do would be to either crank up MaxTableSize or maybe split
	// the transaction out.

	return &badgerBatch{
		db:        d,
		bat:       d.db.NewWriteBatch(),
		namespace: namespace,
		round:     round,
		oldRoot:   oldRoot,
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

func getPreviousRound(tx *badger.Txn, namespace common.Namespace, round uint64) (uint64, error) {
	if round == 0 {
		return 0, nil
	}

	it := tx.NewIterator(badger.IteratorOptions{
		Reverse: true,
		Prefix:  rootLinkKeyFmt.Encode(&namespace),
	})
	defer it.Close()
	// When iterating in reverse, seek moves us to the given key or to the previous
	// key in case the given key does not exist. So this will give us either the
	// queried round or the previous round.
	it.Seek(rootLinkKeyFmt.Encode(&namespace, round))
	if !it.Valid() {
		// No previous round.
		return 0, nil
	}

	// Try to decode the current or previous round as a linkKeyFmt.
	var decNs common.Namespace
	var decRound uint64
	var decHash hash.Hash
	if !rootLinkKeyFmt.Decode(it.Item().Key(), &decNs, &decRound, &decHash) || !decNs.Equal(&namespace) {
		// No previous round.
		return 0, nil
	}

	if decRound == round {
		// Same round, we need to move the iterator and decode again.
		it.Next()
		if !it.Valid() {
			// No previous round.
			return 0, nil
		}

		if !rootLinkKeyFmt.Decode(it.Item().Key(), &decNs, &decRound, &decHash) || !decNs.Equal(&namespace) {
			// No previous round.
			return 0, nil
		}
	}

	return decRound, nil
}

type badgerBatch struct {
	api.BaseBatch

	db  *badgerNodeDB
	bat *badger.WriteBatch

	namespace common.Namespace
	round     uint64
	oldRoot   node.Root

	writeLog     writelog.WriteLog
	annotations  writelog.Annotations
	removedNodes []node.Node
	addedNodes   rootAddedNodes
}

func (ba *badgerBatch) MaybeStartSubtree(subtree api.Subtree, depth node.Depth, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &badgerSubtree{batch: ba}
	}
	return subtree
}

func (ba *badgerBatch) PutWriteLog(writeLog writelog.WriteLog, annotations writelog.Annotations) error {
	ba.writeLog = writeLog
	ba.annotations = annotations
	return nil
}

func (ba *badgerBatch) RemoveNodes(nodes []node.Node) error {
	ba.removedNodes = nodes
	return nil
}

func (ba *badgerBatch) Commit(root node.Root) error {
	if !root.Follows(&ba.oldRoot) {
		return api.ErrRootMustFollowOld
	}

	// Create a separate transaction for reading values. Note that since we are
	// not doing updates in the same transaction this could cause read/write
	// conflicts. We don't care about those due to our storage structure as all
	// writes would write the same or compatible values.
	tx := ba.db.db.NewTransaction(false)
	defer tx.Discard()

	// Get previous round.
	prevRound, err := getPreviousRound(tx, root.Namespace, root.Round)
	if err != nil {
		return err
	}

	// Create root with an empty next link.
	if err = ba.bat.Set(rootLinkKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash), []byte("")); err != nil {
		return errors.Wrap(err, "urkel/db/badger: set returned error")
	}

	// Update the root link for the old root.
	if !ba.oldRoot.Hash.IsEmpty() {
		key := rootLinkKeyFmt.Encode(&ba.oldRoot.Namespace, ba.oldRoot.Round, &ba.oldRoot.Hash)
		if prevRound != ba.oldRoot.Round && ba.oldRoot.Round != root.Round {
			return api.ErrPreviousRoundMismatch
		}

		_, err = tx.Get(key)
		switch err {
		case nil:
		case badger.ErrKeyNotFound:
			return api.ErrRootNotFound
		default:
			return err
		}

		var data []byte
		data, err = root.Hash.MarshalBinary()
		if err != nil {
			return err
		}
		if err = ba.bat.Set(key, data); err != nil {
			return errors.Wrap(err, "urkel/db/badger: set returned error")
		}
	}

	// Mark removed nodes for garbage collection. Updates against the GC index
	// are only applied in case this root is finalized.
	var gcUpdates rootGcUpdates
	for _, n := range ba.removedNodes {
		// Node lives from the round it was created in up to the previous round.
		//
		// NOTE: The node will never be resurrected as the round number is part
		//       of the node hash.
		endRound := prevRound
		if ba.oldRoot.Round == root.Round {
			// If the previous root is in the same round, the node needs to end
			// in the same round instead.
			endRound = root.Round
		}

		h := n.GetHash()
		gcUpdates = append(gcUpdates, rootGcUpdate{
			EndRound:   endRound,
			StartRound: n.GetCreatedRound(),
			Node:       h,
		})
	}
	key := rootGcUpdatesKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash)
	if err = ba.bat.Set(key, cbor.Marshal(gcUpdates)); err != nil {
		return errors.Wrap(err, "urkel/db/badger: set returned error")
	}

	// Store added nodes (only needed until the round is finalized).
	key = rootAddedNodesKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash)
	if err = ba.bat.Set(key, cbor.Marshal(ba.addedNodes)); err != nil {
		return errors.Wrap(err, "urkel/db/badger: set returned error")
	}

	// Store write log.
	if ba.writeLog != nil && ba.annotations != nil {
		log := api.MakeHashedDBWriteLog(ba.writeLog, ba.annotations)

		prefix := writeLogKeyFmt.Encode(&root.Namespace, root.Round, &ba.oldRoot.Hash)
		it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()

		foundOld := false
		for it.Rewind(); it.Valid(); it.Next() {
			var decNs common.Namespace
			var decRound uint64
			var oldRootHash hash.Hash
			var olderRootHash hash.Hash

			if !writeLogKeyFmt.Decode(it.Item().Key(), &decNs, &decRound, &oldRootHash, &olderRootHash) {
				// This should not happen as the Badger iterator should take care of it.
				panic("urkel/db/badger: bad iterator")
			}

			// If an older write log exists, get it, merge it with this one and delete it from the db.
			var oldWriteLog api.HashedDBWriteLog
			err := it.Item().Value(func(data []byte) error {
				return cbor.Unmarshal(data, &oldWriteLog)
			})
			if err != nil {
				return err
			}
			oldWriteLog = append(oldWriteLog, log...)
			bytes := cbor.Marshal(oldWriteLog)
			if err := ba.bat.Set(writeLogKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash, &olderRootHash), bytes); err != nil {
				return errors.Wrap(err, "urkel/db/badger: set merged write log returned error")
			}
			if err := ba.bat.Delete(it.Item().KeyCopy(nil)); err != nil {
				return errors.Wrap(err, "urkel/db/badger: delete partial write log returned error")
			}
			foundOld = true
		}

		if !foundOld {
			bytes := cbor.Marshal(log)
			key := writeLogKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash, &ba.oldRoot.Hash)
			if err := ba.bat.Set(key, bytes); err != nil {
				return errors.Wrap(err, "urkel/db/badger: set new write log returned error")
			}
		}
	}

	if err := ba.bat.Flush(); err != nil {
		return err
	}

	ba.writeLog = nil
	ba.annotations = nil
	ba.removedNodes = nil
	ba.addedNodes = nil

	return ba.BaseBatch.Commit(root)
}

func (ba *badgerBatch) Reset() {
	ba.bat.Cancel()
	ba.writeLog = nil
	ba.annotations = nil
	ba.removedNodes = nil
	ba.addedNodes = nil
}

type badgerSubtree struct {
	batch *badgerBatch
}

func (s *badgerSubtree) PutNode(depth node.Depth, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	h := ptr.Node.GetHash()
	s.batch.addedNodes = append(s.batch.addedNodes, h)
	if err = s.batch.bat.Set(nodeKeyFmt.Encode(&s.batch.namespace, &h), data); err != nil {
		return err
	}
	return nil
}

func (s *badgerSubtree) VisitCleanNode(depth node.Depth, ptr *node.Pointer) error {
	return nil
}

func (s *badgerSubtree) Commit() error {
	return nil
}

// NewLogAdapter returns a badger.Logger backed by an ekiden logger.
func NewLogAdapter(logger *logging.Logger) badger.Logger {
	return &badgerLogger{
		logger: logger,
	}
}

type badgerLogger struct {
	logger *logging.Logger
}

func (l *badgerLogger) Errorf(format string, a ...interface{}) {
	l.logger.Error(strings.TrimSpace(fmt.Sprintf(format, a...)))
}

func (l *badgerLogger) Warningf(format string, a ...interface{}) {
	l.logger.Warn(strings.TrimSpace(fmt.Sprintf(format, a...)))
}

func (l *badgerLogger) Infof(format string, a ...interface{}) {
	l.logger.Info(strings.TrimSpace(fmt.Sprintf(format, a...)))
}

func (l *badgerLogger) Debugf(format string, a ...interface{}) {
	l.logger.Debug(strings.TrimSpace(fmt.Sprintf(format, a...)))
}
