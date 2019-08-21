// Package leveldb provides a LevelDB-backed node database.
package leveldb

import (
	"context"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

var (
	_ api.NodeDB = (*leveldbNodeDB)(nil)

	// TODO: Storing the full namespace with each node seems quite inefficient.

	// nodeKeyFmt is the key format for nodes (namespace, node hash).
	//
	// Value is serialized node.
	nodeKeyFmt = api.NewKeyFormat('N', &common.Namespace{}, &hash.Hash{})
	// writeLogKeyFmt is the key format for write logs (namespace, round,
	// old root, new root).
	//
	// Value is CBOR-serialized write log.
	writeLogKeyFmt = api.NewKeyFormat('L', &common.Namespace{}, uint64(0), &hash.Hash{}, &hash.Hash{})
	// rootLinkKeyFmt is the key format for the root links (namespace, round,
	// root).
	//
	// Value is next root hash.
	rootLinkKeyFmt = api.NewKeyFormat('M', &common.Namespace{}, uint64(0), &hash.Hash{})
	// rootGcUpdatesKeyFmt is the key format for the pending garbage collection
	// index updates that need to be applied only in case the given root is among
	// the finalized roots. The key format is (namespace, round, root).
	//
	// Value is CBOR-serialized list of updates for garbage collection index.
	rootGcUpdatesKeyFmt = api.NewKeyFormat('I', &common.Namespace{}, uint64(0), &hash.Hash{})
	// rootAddedNodesKeyFmt is the key format for the pending added nodes for the
	// given root that need to be removed only in case the given root is not among
	// the finalized roots. They key format is (namespace, round, root).
	//
	// Value is CBOR-serialized list of node hashes.
	rootAddedNodesKeyFmt = api.NewKeyFormat('J', &common.Namespace{}, uint64(0), &hash.Hash{})
	// gcIndexKeyFmt is the key format for the garbage collection index
	// (namespace, end round, start round, node hash).
	//
	// Value is empty.
	gcIndexKeyFmt = api.NewKeyFormat('G', &common.Namespace{}, uint64(0), uint64(0), &hash.Hash{})
	// finalizedKeyFmt is the key format for the last finalized round number.
	//
	// Value is the last finalized round number.
	finalizedKeyFmt = api.NewKeyFormat('F', &common.Namespace{})

	batchPool = sync.Pool{
		New: func() interface{} {
			return new(leveldb.Batch)
		},
	}
)

// maxBatchSize is the maximum number of nodes stored in a batch before
// the batch will be flushed to the database (without fsync).
const maxBatchSize = 100

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

type leveldbNodeDB struct {
	api.CheckpointableDB

	db *leveldb.DB

	closeOnce sync.Once
}

// New creates a new LevelDB-backed node database.
func New(dirname string) (api.NodeDB, error) {
	db, err := leveldb.OpenFile(dirname, nil)
	if err != nil {
		return nil, err
	}
	levelNDb := &leveldbNodeDB{db: db}
	levelNDb.CheckpointableDB = api.NewCheckpointableDB(levelNDb)
	return levelNDb, nil
}

func (d *leveldbNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/leveldb: attempted to get invalid pointer from node database")
	}

	bytes, err := d.db.Get(nodeKeyFmt.Encode(&root.Namespace, &ptr.Hash), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			err = api.ErrNodeNotFound
		}
		return nil, err
	}

	return node.UnmarshalBinary(bytes)
}

func (d *leveldbNodeDB) GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (api.WriteLogIterator, error) {
	if !endRoot.Follows(&startRoot) {
		return nil, api.ErrRootMustFollowOld
	}

	key := writeLogKeyFmt.Encode(&endRoot.Namespace, endRoot.Round, &startRoot.Hash, &endRoot.Hash)
	bytes, err := d.db.Get(key, nil)
	if err != nil {
		return nil, err
	}

	var log api.HashedDBWriteLog
	if err := cbor.Unmarshal(bytes, &log); err != nil {
		return nil, err
	}

	return api.ReviveHashedDBWriteLog(ctx, log, func(h hash.Hash) (*node.LeafNode, error) {
		leaf, err := d.GetNode(endRoot, &node.Pointer{Hash: h, Clean: true})
		if err != nil {
			return nil, err
		}
		return leaf.(*node.LeafNode), nil
	})
}

func (d *leveldbNodeDB) HasRoot(root node.Root) bool {
	// An empty root is always implicitly present.
	if root.Hash.IsEmpty() {
		return true
	}

	exists, err := d.db.Has(rootLinkKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash), nil)
	if err != nil {
		panic(err)
	}
	return exists
}

func (d *leveldbNodeDB) Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error {
	batch := batchPool.Get().(*leveldb.Batch)
	defer func() {
		batch.Reset()
		batchPool.Put(batch)
		batch = nil
	}()

	// Get a database snapshot for consistent queries.
	snapshot, err := d.db.GetSnapshot()
	if err != nil {
		return err
	}
	defer snapshot.Release()

	// Make sure that the previous round has been finalized.
	data, err := snapshot.Get(finalizedKeyFmt.Encode(&namespace), nil)
	switch err {
	case nil:
		var lastFinalizedRound uint64
		if err = cbor.Unmarshal(data, &lastFinalizedRound); err != nil {
			panic("urkel/db/leveldb: corrupted finalized round index")
		}

		if round > 0 && lastFinalizedRound < (round-1) {
			return api.ErrNotFinalized
		}

		// Make sure that this round has not yet been finalized.
		if round <= lastFinalizedRound {
			return api.ErrAlreadyFinalized
		}
	default:
		// No previous round has been finalized.
		if round > 0 {
			return api.ErrNotFinalized
		}
	}
	// Update last finalized round.
	batch.Put(finalizedKeyFmt.Encode(&namespace), cbor.Marshal(round))

	// Determine a set of finalized roots. Finalization is transitive, so if
	// a parent root is finalized the child should be consider finalized too.
	finalizedRoots := make(map[hash.Hash]bool)
	for _, rootHash := range roots {
		finalizedRoots[rootHash] = true
	}

	for updated := true; updated; {
		updated = false

		prefix := rootLinkKeyFmt.Encode(&namespace, round)
		it := snapshot.NewIterator(util.BytesPrefix(prefix), nil)
		defer it.Release()

		for it.Next() {
			// If next root hash is among the finalized roots, add this root as well.
			var decNs common.Namespace
			var decRound uint64
			var rootHash hash.Hash

			if !rootLinkKeyFmt.Decode(it.Key(), &decNs, &decRound, &rootHash) {
				// This should not happen as the LevelDB iterator should take care of it.
				panic("urkel/db/leveldb: bad iterator")
			}

			if value := it.Value(); len(value) > 0 {
				var nextRoot hash.Hash
				if err := nextRoot.UnmarshalBinary(value); err != nil {
					panic("urkel/db/leveldb: corrupted root link index")
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
	it := snapshot.NewIterator(util.BytesPrefix(prefix), nil)
	defer it.Release()

	maybeLoneNodes := make(map[hash.Hash]bool)
	notLoneNodes := make(map[hash.Hash]bool)

	for it.Next() {
		var decNs common.Namespace
		var decRound uint64
		var rootHash hash.Hash

		if !rootLinkKeyFmt.Decode(it.Key(), &decNs, &decRound, &rootHash) {
			// This should not happen as the LevelDB iterator should take care of it.
			panic("urkel/db/leveldb: bad iterator")
		}

		rootGcUpdatesKey := rootGcUpdatesKeyFmt.Encode(&namespace, round, &rootHash)
		rootAddedNodesKey := rootAddedNodesKeyFmt.Encode(&namespace, round, &rootHash)

		// Load hashes of nodes added during this round for this root.
		data, err := snapshot.Get(rootAddedNodesKey, nil)
		if err != nil {
			panic("urkel/db/leveldb: corrupted root added nodes index")
		}

		var addedNodes rootAddedNodes
		if err = cbor.Unmarshal(data, &addedNodes); err != nil {
			panic("urkel/db/leveldb: corrupted root added nodes index")
		}

		if finalizedRoots[rootHash] {
			// Commit garbage collection index updates for any finalized roots.
			data, err = snapshot.Get(rootGcUpdatesKey, nil)
			if err != nil {
				panic("urkel/db/leveldb: corrupted root gc updates index")
			}

			var gcUpdates rootGcUpdates
			if err := cbor.Unmarshal(data, &gcUpdates); err != nil {
				panic("urkel/db/leveldb: corrupted root gc updates index")
			}

			for _, u := range gcUpdates {
				key := gcIndexKeyFmt.Encode(&namespace, u.EndRound, u.StartRound, &u.Node)
				batch.Put(key, []byte(""))
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
			batch.Delete(it.Key())
		}

		// GC updates no longer needed after finalization.
		batch.Delete(rootGcUpdatesKey)
		// Set of added nodes no longer needed after finalization.
		batch.Delete(rootAddedNodesKey)
	}

	// Clean any lone nodes.
	for h := range maybeLoneNodes {
		if notLoneNodes[h] {
			continue
		}

		key := nodeKeyFmt.Encode(&namespace, &h)
		batch.Delete(key)
	}

	// Commit batch.
	if err := d.db.Write(batch, &opt.WriteOptions{Sync: true}); err != nil {
		return err
	}

	return nil
}

func (d *leveldbNodeDB) Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error) {
	var pruned int

	batch := batchPool.Get().(*leveldb.Batch)
	defer func() {
		batch.Reset()
		batchPool.Put(batch)
		batch = nil
	}()

	// Get a database snapshot for consistent queries.
	snapshot, err := d.db.GetSnapshot()
	if err != nil {
		return 0, err
	}
	defer snapshot.Release()

	// Make sure that the round that we try to prune has been finalized.
	data, err := snapshot.Get(finalizedKeyFmt.Encode(&namespace), nil)
	if err != nil {
		return 0, api.ErrNotFinalized
	}

	var lastFinalizedRound uint64
	if err = cbor.Unmarshal(data, &lastFinalizedRound); err != nil {
		panic("urkel/db/leveldb: corrupted finalized round index")
	}

	if lastFinalizedRound < round {
		return 0, api.ErrNotFinalized
	}

	prevRound, err := getPreviousRound(snapshot, namespace, round)
	if err != nil {
		return 0, err
	}

	pruneHashes := make(map[hash.Hash]bool)

	// Iterate over all lifetimes that end in the passed round.
	prefix := gcIndexKeyFmt.Encode(&namespace, round)
	it := snapshot.NewIterator(util.BytesPrefix(prefix), nil)
	defer it.Release()

	for it.Next() {
		var decNs common.Namespace
		var endRound uint64
		var startRound uint64
		var h hash.Hash

		if !gcIndexKeyFmt.Decode(it.Key(), &decNs, &endRound, &startRound, &h) {
			// This should not happen as the LevelDB iterator should take care of it.
			panic("urkel/db/leveldb: bad iterator")
		}

		batch.Delete(it.Key())

		if startRound > prevRound || startRound == endRound {
			// Either start round is after the previous round or the node starts and
			// terminates in the same round. Prune the node(s).
			pruneHashes[h] = true
		} else {
			// Since the current round is being pruned, the lifetime ends at the
			// previous round.
			batch.Put(gcIndexKeyFmt.Encode(&decNs, prevRound, startRound, &h), []byte(""))
		}
	}

	// Prune all roots in round.
	prefix = rootLinkKeyFmt.Encode(&namespace, round)
	it = snapshot.NewIterator(util.BytesPrefix(prefix), nil)
	defer it.Release()

	for it.Next() {
		// Prune lone roots (e.g., roots that start in the pruned round and don't
		// have any derived roots in following rounds).
		if len(it.Value()) == 0 {
			var decNs common.Namespace
			var decRound uint64
			var rootHash hash.Hash

			if !rootLinkKeyFmt.Decode(it.Key(), &decNs, &decRound, &rootHash) {
				// This should not happen as the LevelDB iterator should take care of it.
				panic("urkel/db/leveldb: bad iterator")
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

		batch.Delete(it.Key())
	}

	// Prune all write logs in round.
	prefix = writeLogKeyFmt.Encode(&namespace, round)
	it = snapshot.NewIterator(util.BytesPrefix(prefix), nil)
	defer it.Release()

	for it.Next() {
		batch.Delete(it.Key())
	}

	// Prune all collected hashes.
	for h := range pruneHashes {
		batch.Delete(nodeKeyFmt.Encode(&namespace, &h))
		pruned++
	}

	// Commit batch.
	if err := d.db.Write(batch, &opt.WriteOptions{Sync: true}); err != nil {
		return 0, err
	}

	return pruned, nil
}

func (d *leveldbNodeDB) Close() {
	d.closeOnce.Do(func() {
		_ = d.db.Close()
	})
}

func getPreviousRound(snapshot *leveldb.Snapshot, namespace common.Namespace, round uint64) (uint64, error) {
	if round == 0 {
		return 0, nil
	}

	it := snapshot.NewIterator(nil, nil)
	defer it.Release()
	// Seek moves us to a key that is equal or greater than the passed key, so
	// this should give us the either the requested round or one key after the
	// requested round.
	it.Seek(rootLinkKeyFmt.Encode(&namespace, round))
	if !it.Prev() {
		return 0, nil
	}

	// Try to decode the previous round as a linkKeyFmt.
	var decNs common.Namespace
	var decRound uint64
	var decHash hash.Hash
	if !rootLinkKeyFmt.Decode(it.Key(), &decNs, &decRound, &decHash) || !decNs.Equal(&namespace) {
		// No previous round.
		return 0, nil
	}

	return decRound, nil
}

type leveldbBatch struct {
	api.BaseBatch

	db  *leveldbNodeDB
	bat *leveldb.Batch

	nodes int

	namespace common.Namespace
	round     uint64
	oldRoot   node.Root

	writeLog     writelog.WriteLog
	annotations  writelog.WriteLogAnnotations
	removedNodes []node.Node
	addedNodes   rootAddedNodes
}

func (d *leveldbNodeDB) NewBatch(namespace common.Namespace, round uint64, oldRoot node.Root) api.Batch {
	return &leveldbBatch{
		db:        d,
		bat:       batchPool.Get().(*leveldb.Batch),
		namespace: namespace,
		round:     round,
		oldRoot:   oldRoot,
	}
}

func (b *leveldbBatch) MaybeStartSubtree(subtree api.Subtree, depth node.Depth, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &leveldbSubtree{batch: b}
	}
	return subtree
}

func (b *leveldbBatch) PutWriteLog(writeLog writelog.WriteLog, annotations writelog.WriteLogAnnotations) error {
	b.writeLog = writeLog
	b.annotations = annotations
	return nil
}

func (b *leveldbBatch) RemoveNodes(nodes []node.Node) error {
	b.removedNodes = nodes
	return nil
}

func (b *leveldbBatch) Commit(root node.Root) error {
	if !root.Follows(&b.oldRoot) {
		return api.ErrRootMustFollowOld
	}

	// Get a database snapshot for consistent queries.
	snapshot, err := b.db.db.GetSnapshot()
	if err != nil {
		return err
	}
	defer snapshot.Release()

	// Get previous round.
	prevRound, err := getPreviousRound(snapshot, root.Namespace, root.Round)
	if err != nil {
		return err
	}

	// Create root with an empty next link.
	b.bat.Put(rootLinkKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash), []byte(""))

	// Update the root link for the old root.
	if !b.oldRoot.Hash.IsEmpty() {
		key := rootLinkKeyFmt.Encode(&b.oldRoot.Namespace, b.oldRoot.Round, &b.oldRoot.Hash)
		if prevRound != b.oldRoot.Round && b.oldRoot.Round != root.Round {
			return api.ErrPreviousRoundMismatch
		}

		exists, err := snapshot.Has(key, nil)
		if err != nil {
			return err
		}
		if !exists {
			return api.ErrRootNotFound
		}

		data, err := root.Hash.MarshalBinary()
		if err != nil {
			return err
		}
		b.bat.Put(key, data)
	}

	// Mark removed nodes for garbage collection. Updates against the GC index
	// are only applied in case this root is finalized.
	var gcUpdates rootGcUpdates
	for _, n := range b.removedNodes {
		// Node lives from the round it was created in up to the previous round.
		//
		// NOTE: The node will never be resurrected as the round number is part
		//       of the node hash.
		endRound := prevRound
		if b.oldRoot.Round == root.Round {
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
	b.bat.Put(rootGcUpdatesKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash), cbor.Marshal(gcUpdates))

	// Store added nodes (only needed until the round is finalized).
	b.bat.Put(rootAddedNodesKeyFmt.Encode(&root.Namespace, root.Round, &root.Hash), cbor.Marshal(b.addedNodes))

	// Store write log.
	if b.writeLog != nil && b.annotations != nil {
		log := api.MakeHashedDBWriteLog(b.writeLog, b.annotations)
		bytes := cbor.Marshal(log)
		key := writeLogKeyFmt.Encode(&root.Namespace, root.Round, &b.oldRoot.Hash, &root.Hash)
		b.bat.Put(key, bytes)
	}

	if err := b.db.db.Write(b.bat, &opt.WriteOptions{Sync: true}); err != nil {
		return err
	}

	b.Reset()

	return b.BaseBatch.Commit(root)
}

func (b *leveldbBatch) Reset() {
	if b.bat == nil {
		return
	}

	b.bat.Reset()
	batchPool.Put(b.bat)
	b.bat = nil
	b.nodes = 0
	b.writeLog = nil
	b.annotations = nil
	b.removedNodes = nil
	b.addedNodes = nil
}

type leveldbSubtree struct {
	batch *leveldbBatch
}

func (s *leveldbSubtree) PutNode(depth node.Depth, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	h := ptr.Node.GetHash()
	s.batch.bat.Put(nodeKeyFmt.Encode(&s.batch.namespace, &h), data)
	s.batch.nodes++
	s.batch.addedNodes = append(s.batch.addedNodes, h)
	if s.batch.nodes >= maxBatchSize {
		// If we reach the maximum batch size, commit early.
		if err := s.batch.db.db.Write(s.batch.bat, &opt.WriteOptions{Sync: false}); err != nil {
			return err
		}
		s.batch.bat.Reset()
		s.batch.nodes = 0
	}

	return nil
}

func (s *leveldbSubtree) VisitCleanNode(depth node.Depth, ptr *node.Pointer) error {
	return nil
}

func (s *leveldbSubtree) Commit() error {
	return nil
}
