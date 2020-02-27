// Package badger provides a Badger-backed node database.
package badger

import (
	"context"
	"fmt"
	"sync"

	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common"
	cmnBadger "github.com/oasislabs/oasis-core/go/common/badger"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/writelog"
)

const dbVersion = 1

var (
	_ api.NodeDB = (*badgerNodeDB)(nil)

	// nodeKeyFmt is the key format for nodes (node hash).
	//
	// Value is serialized node.
	nodeKeyFmt = keyformat.New(0x00, &hash.Hash{})
	// writeLogKeyFmt is the key format for write logs (round, new root,
	// old root).
	//
	// Value is CBOR-serialized write log.
	writeLogKeyFmt = keyformat.New(0x01, uint64(0), &hash.Hash{}, &hash.Hash{})
	// rootLinkKeyFmt is the key format for the root links (round, src root,
	// dst root).
	//
	// Value is empty.
	rootLinkKeyFmt = keyformat.New(0x02, uint64(0), &hash.Hash{}, &hash.Hash{})
	// rootGcUpdatesKeyFmt is the key format for the pending garbage collection
	// index updates that need to be applied only in case the given root is among
	// the finalized roots. The key format is (round, root).
	//
	// Value is CBOR-serialized list of updates for garbage collection index.
	rootGcUpdatesKeyFmt = keyformat.New(0x03, uint64(0), &hash.Hash{})
	// rootAddedNodesKeyFmt is the key format for the pending added nodes for the
	// given root that need to be removed only in case the given root is not among
	// the finalized roots. They key format is (round, root).
	//
	// Value is CBOR-serialized list of node hashes.
	rootAddedNodesKeyFmt = keyformat.New(0x04, uint64(0), &hash.Hash{})
	// gcIndexKeyFmt is the key format for the garbage collection index
	// (end round, start round, node hash).
	//
	// Value is empty.
	gcIndexKeyFmt = keyformat.New(0x05, uint64(0), uint64(0), &hash.Hash{})
	// finalizedKeyFmt is the key format for the last finalized round number.
	//
	// Value is the last finalized round number.
	finalizedKeyFmt = keyformat.New(0x06)
	// metadataKeyFmt is the key format for metadata.
	//
	// Value is CBOR-serialized metadata.
	metadataKeyFmt = keyformat.New(0x07)
)

// rootGcIndexUpdate is an element of the rootGcUpdates list.
type rootGcUpdate struct {
	_ struct{} `cbor:",toarray"` //nolint

	EndRound   uint64
	StartRound uint64
	Node       hash.Hash
}

// rootGcIndexUpdates is the value of the rootGcUpdates keys.
type rootGcUpdates []rootGcUpdate

// rootAddedNodes is the value of the rootAddedNodes keys.
type rootAddedNodes []hash.Hash

// metadata is the database metadata.
type metadata struct {
	sync.RWMutex `json:"-"`

	// Version is the database schema version.
	Version uint64 `json:"version"`
	// Namespace is the namespace this database is for.
	Namespace common.Namespace `json:"namespace"`

	lastFinalizedRound *uint64
}

func (m *metadata) getLastFinalizedRound() (uint64, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.lastFinalizedRound == nil {
		return 0, false
	}
	return *m.lastFinalizedRound, true
}

func (m *metadata) setLastFinalizedRound(round uint64) {
	m.Lock()
	defer m.Unlock()

	if m.lastFinalizedRound != nil && round <= *m.lastFinalizedRound {
		return
	}

	m.lastFinalizedRound = &round
}

// New creates a new BadgerDB-backed node database.
func New(cfg *api.Config) (api.NodeDB, error) {
	db := &badgerNodeDB{
		logger:    logging.GetLogger("urkel/db/badger"),
		namespace: cfg.Namespace,
	}

	opts := badger.DefaultOptions(cfg.DB)
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(db.logger))
	opts = opts.WithSyncWrites(!cfg.DebugNoFsync)
	// Allow value log truncation if required (this is needed to recover the
	// value log file which can get corrupted in crashes).
	opts = opts.WithTruncate(true)
	opts = opts.WithCompression(options.None)
	opts = opts.WithMaxCacheSize(cfg.MaxCacheSize)

	var err error
	if db.db, err = badger.Open(opts); err != nil {
		return nil, errors.Wrap(err, "urkel/db/badger: failed to open database")
	}

	// Load database metadata.
	if err = db.load(); err != nil {
		_ = db.db.Close()
		return nil, errors.Wrap(err, "urkel/db/badger: failed to load metadata")
	}

	db.gc = cmnBadger.NewGCWorker(db.logger, db.db)

	return db, nil
}

type badgerNodeDB struct {
	logger *logging.Logger

	namespace common.Namespace

	db   *badger.DB
	gc   *cmnBadger.GCWorker
	meta metadata

	closeOnce sync.Once
}

func (d *badgerNodeDB) load() error {
	return d.db.Update(func(tx *badger.Txn) error {
		// Load metadata.
		item, err := tx.Get(metadataKeyFmt.Encode())
		switch err {
		case nil:
			// Metadata already exists, just load it and verify that it is
			// compatible with what we have here.
			err = item.Value(func(data []byte) error {
				return cbor.Unmarshal(data, &d.meta)
			})
			if err != nil {
				return err
			}

			if d.meta.Version != dbVersion {
				return fmt.Errorf("incompatible database version (expected: %d got: %d)",
					dbVersion,
					d.meta.Version,
				)
			}
			if !d.meta.Namespace.Equal(&d.namespace) {
				return fmt.Errorf("incompatible namespace (expected: %s got: %s)",
					d.namespace,
					d.meta.Namespace,
				)
			}

			// Load last finalized round.
			item, err = tx.Get(finalizedKeyFmt.Encode())
			switch err {
			case nil:
				return item.Value(func(data []byte) error {
					return cbor.Unmarshal(data, &d.meta.lastFinalizedRound)
				})
			case badger.ErrKeyNotFound:
				return nil
			default:
				return err
			}
		case badger.ErrKeyNotFound:
		default:
			return err
		}

		// No metadata exists, create some.
		d.meta.Version = dbVersion
		d.meta.Namespace = d.namespace
		return tx.Set(metadataKeyFmt.Encode(), cbor.Marshal(&d.meta))
	})
}

func (d *badgerNodeDB) sanityCheckNamespace(ns common.Namespace) error {
	if !ns.Equal(&d.namespace) {
		return api.ErrBadNamespace
	}
	return nil
}

func (d *badgerNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/badger: attempted to get invalid pointer from node database")
	}
	if err := d.sanityCheckNamespace(root.Namespace); err != nil {
		return nil, err
	}

	tx := d.db.NewTransaction(false)
	defer tx.Discard()
	item, err := tx.Get(nodeKeyFmt.Encode(&ptr.Hash))
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
	if err := d.sanityCheckNamespace(startRoot.Namespace); err != nil {
		return nil, err
	}

	tx := d.db.NewTransaction(false)
	defer tx.Discard()

	// Start at the end root and search towards the start root. This assumes that the
	// chains are not long and that there is not a lot of forks as in that case performance
	// would suffer.
	//
	// In reality the two common cases are:
	// - State updates: s -> s' (a single hop)
	// - I/O updates: empty -> i -> io (two hops)
	//
	// For this reason, we currently refuse to traverse more than two hops.
	const maxAllowedHops = 2

	type wlItem struct {
		depth       uint8
		endRootHash hash.Hash
		logKeys     [][]byte
		logRoots    []hash.Hash
	}
	// NOTE: We could use a proper deque, but as long as we keep the number of hops and
	//       forks low, this should not be a problem.
	queue := []*wlItem{&wlItem{depth: 0, endRootHash: endRoot.Hash}}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		curItem := queue[0]
		queue = queue[1:]

		wl, err := func() (writelog.Iterator, error) {
			// Iterate over all write logs that result in the current item.
			prefix := writeLogKeyFmt.Encode(endRoot.Round, &curItem.endRootHash)
			it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
			defer it.Close()

			for it.Rewind(); it.Valid(); it.Next() {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}

				item := it.Item()

				var decRound uint64
				var decEndRootHash hash.Hash
				var decStartRootHash hash.Hash

				if !writeLogKeyFmt.Decode(item.Key(), &decRound, &decEndRootHash, &decStartRootHash) {
					// This should not happen as the Badger iterator should take care of it.
					panic("urkel/db/badger: bad iterator")
				}

				nextItem := wlItem{
					depth:       curItem.depth + 1,
					endRootHash: decStartRootHash,
					// Only store log keys to avoid keeping everything in memory while
					// we are searching for the right path.
					logKeys:  append(curItem.logKeys, item.KeyCopy(nil)),
					logRoots: append(curItem.logRoots, curItem.endRootHash),
				}
				if nextItem.endRootHash.Equal(&startRoot.Hash) {
					// Path has been found, deserialize and stream write logs.
					var index int
					pipeTx := d.db.NewTransaction(false)
					return api.ReviveHashedDBWriteLogs(ctx,
						func() (node.Root, api.HashedDBWriteLog, error) {
							if index >= len(nextItem.logKeys) {
								return node.Root{}, nil, nil
							}

							key := nextItem.logKeys[index]
							root := node.Root{
								Namespace: endRoot.Namespace,
								Round:     endRoot.Round,
								Hash:      nextItem.logRoots[index],
							}

							item, err := pipeTx.Get(key)
							if err != nil {
								return node.Root{}, nil, err
							}

							var log api.HashedDBWriteLog
							err = item.Value(func(data []byte) error {
								return cbor.Unmarshal(data, &log)
							})
							if err != nil {
								return node.Root{}, nil, err
							}

							index++
							return root, log, nil
						},
						func(root node.Root, h hash.Hash) (*node.LeafNode, error) {
							leaf, err := d.GetNode(root, &node.Pointer{Hash: h, Clean: true})
							if err != nil {
								return nil, err
							}
							return leaf.(*node.LeafNode), nil
						},
						func() {
							pipeTx.Discard()
						},
					)
				}

				if nextItem.depth < maxAllowedHops {
					queue = append(queue, &nextItem)
				}
			}

			return nil, nil
		}()
		if wl != nil || err != nil {
			return wl, err
		}
	}

	return nil, api.ErrWriteLogNotFound
}

func (d *badgerNodeDB) HasRoot(root node.Root) bool {
	if err := d.sanityCheckNamespace(root.Namespace); err != nil {
		return false
	}

	// An empty root is always implicitly present.
	if root.Hash.IsEmpty() {
		return true
	}

	var emptyHash hash.Hash
	emptyHash.Empty()

	err := d.db.View(func(tx *badger.Txn) error {
		_, err := tx.Get(rootLinkKeyFmt.Encode(root.Round, &root.Hash, &emptyHash))
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
	if err := d.sanityCheckNamespace(namespace); err != nil {
		return err
	}

	// We don't need to put the operations into a write transaction as the
	// content of the node database is based on immutable keys, so multiple
	// concurrent prunes cannot cause corruption.
	batch := d.db.NewWriteBatch()
	defer batch.Cancel()
	tx := d.db.NewTransaction(false)
	defer tx.Discard()

	// Make sure that the previous round has been finalized.
	lastFinalizedRound, exists := d.meta.getLastFinalizedRound()
	if round > 0 && exists && lastFinalizedRound < (round-1) {
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

		prefix := rootLinkKeyFmt.Encode(round)
		it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			// If next root hash is among the finalized roots, add this root as well.
			var decRound uint64
			var rootHash hash.Hash
			var nextRoot hash.Hash

			if !rootLinkKeyFmt.Decode(item.Key(), &decRound, &rootHash, &nextRoot) {
				// This should not happen as the Badger iterator should take care of it.
				panic("urkel/db/badger: bad iterator")
			}

			if nextRoot.IsEmpty() {
				continue
			}
			if !finalizedRoots[rootHash] && finalizedRoots[nextRoot] {
				finalizedRoots[rootHash] = true
				updated = true
			}
		}
	}

	// Go through all roots and either commit GC updates or prune them based on
	// whether they are included in the finalized roots or not.
	prefix := rootLinkKeyFmt.Encode(round)
	it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	maybeLoneNodes := make(map[hash.Hash]bool)
	notLoneNodes := make(map[hash.Hash]bool)

	for it.Rewind(); it.Valid(); it.Next() {
		var decRound uint64
		var rootHash hash.Hash
		var nextRoot hash.Hash

		if !rootLinkKeyFmt.Decode(it.Item().Key(), &decRound, &rootHash, &nextRoot) {
			// This should not happen as the Badger iterator should take care of it.
			panic("urkel/db/badger: bad iterator")
		}
		// Skip all actual links to avoid processing the same root multiple times.
		if !nextRoot.IsEmpty() {
			// We still need to remove the links for non-finalized roots.
			if !finalizedRoots[rootHash] {
				if err := batch.Delete(it.Item().KeyCopy(nil)); err != nil {
					return err
				}
			}
			continue
		}

		rootGcUpdatesKey := rootGcUpdatesKeyFmt.Encode(round, &rootHash)
		rootAddedNodesKey := rootAddedNodesKeyFmt.Encode(round, &rootHash)

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
				key := gcIndexKeyFmt.Encode(u.EndRound, u.StartRound, &u.Node)
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

			// Remove write logs for the non-finalized root.
			if err = func() error {
				rootWriteLogsPrefix := writeLogKeyFmt.Encode(round, &rootHash)
				wit := tx.NewIterator(badger.IteratorOptions{Prefix: rootWriteLogsPrefix})
				defer wit.Close()

				for wit.Rewind(); wit.Valid(); wit.Next() {
					if err = batch.Delete(wit.Item().KeyCopy(nil)); err != nil {
						return err
					}
				}
				return nil
			}(); err != nil {
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

		key := nodeKeyFmt.Encode(&h)
		if err := batch.Delete(key); err != nil {
			return err
		}
	}

	// Update last finalized round. This is done at the end as Badger may
	// split the batch into multiple transactions.
	if err := batch.Set(finalizedKeyFmt.Encode(), cbor.Marshal(round)); err != nil {
		return err
	}

	// Commit batch.
	if err := batch.Flush(); err != nil {
		return err
	}

	// Update cached last finalized round.
	d.meta.setLastFinalizedRound(round)

	return nil
}

func (d *badgerNodeDB) Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error) {
	if err := d.sanityCheckNamespace(namespace); err != nil {
		return 0, err
	}

	// We don't need to put the operations into a write transaction as the
	// content of the node database is based on immutable keys, so multiple
	// concurrent prunes cannot cause corruption.
	batch := d.db.NewWriteBatch()
	defer batch.Cancel()
	tx := d.db.NewTransaction(false)
	defer tx.Discard()

	// Make sure that the round that we try to prune has been finalized.
	lastFinalizedRound, exists := d.meta.getLastFinalizedRound()
	if !exists || lastFinalizedRound < round {
		return 0, api.ErrNotFinalized
	}

	prevRound, err := getPreviousRound(tx, round)
	if err != nil {
		return 0, err
	}

	pruneHashes := make(map[hash.Hash]bool)

	// Iterate over all lifetimes that end in the passed round.
	prefix := gcIndexKeyFmt.Encode(round)
	it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		var endRound uint64
		var startRound uint64
		var h hash.Hash

		if !gcIndexKeyFmt.Decode(it.Item().Key(), &endRound, &startRound, &h) {
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
			if err = batch.Set(gcIndexKeyFmt.Encode(prevRound, startRound, &h), []byte("")); err != nil {
				return 0, err
			}
		}
	}

	// Prune all roots in round.
	prefix = rootLinkKeyFmt.Encode(round)
	it = tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	maybeLoneRoots := make(map[hash.Hash]bool)
	for it.Rewind(); it.Valid(); it.Next() {
		item := it.Item()

		var decRound uint64
		var rootHash hash.Hash
		var nextRoot hash.Hash

		if !rootLinkKeyFmt.Decode(item.Key(), &decRound, &rootHash, &nextRoot) {
			// This should not happen as the iterator should take care of it.
			panic("urkel/db/badger: bad iterator")
		}

		if nextRoot.IsEmpty() {
			// Need to only set the flag iff the flag has not already been set
			// to either value before.
			if _, ok := maybeLoneRoots[rootHash]; !ok {
				maybeLoneRoots[rootHash] = true
			}
		} else {
			maybeLoneRoots[rootHash] = false
		}

		if err = batch.Delete(item.KeyCopy(nil)); err != nil {
			return 0, err
		}
	}
	for rootHash, isLone := range maybeLoneRoots {
		if !isLone {
			continue
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

	// Prune all write logs in round.
	prefix = writeLogKeyFmt.Encode(round)
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
		if err = batch.Delete(nodeKeyFmt.Encode(&h)); err != nil {
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

func (d *badgerNodeDB) NewBatch(oldRoot node.Root, chunk bool) api.Batch {
	// WARNING: There is a maximum batch size and maximum batch entry count.
	// Both of these things are derived from the MaxTableSize option.
	//
	// The size limit also applies to normal transactions, so the "right"
	// thing to do would be to either crank up MaxTableSize or maybe split
	// the transaction out.

	return &badgerBatch{
		db:      d,
		bat:     d.db.NewWriteBatch(),
		oldRoot: oldRoot,
		chunk:   chunk,
	}
}

func (d *badgerNodeDB) Close() {
	d.closeOnce.Do(func() {
		d.gc.Close()

		if err := d.db.Close(); err != nil {
			d.logger.Error("close returned error",
				"err", err,
			)
		}
	})
}

func getPreviousRound(tx *badger.Txn, round uint64) (uint64, error) {
	if round == 0 {
		return 0, nil
	}

	it := tx.NewIterator(badger.IteratorOptions{
		Reverse: true,
		Prefix:  rootLinkKeyFmt.Encode(),
	})
	defer it.Close()
	// When iterating in reverse, seek moves us to the given key or to the previous
	// key in case the given key does not exist. So this will give us either the
	// queried round or the previous round.
	it.Seek(rootLinkKeyFmt.Encode(round))
	if !it.Valid() {
		// No previous round.
		return 0, nil
	}

	// Try to decode the current or previous round as a linkKeyFmt.
	var decRound uint64
	if !rootLinkKeyFmt.Decode(it.Item().Key(), &decRound) {
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

		if !rootLinkKeyFmt.Decode(it.Item().Key(), &decRound) {
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

	oldRoot node.Root
	chunk   bool

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
	if ba.chunk {
		return fmt.Errorf("urkel/db/badger: cannot put write log in chunk mode")
	}

	ba.writeLog = writeLog
	ba.annotations = annotations
	return nil
}

func (ba *badgerBatch) RemoveNodes(nodes []node.Node) error {
	if ba.chunk {
		return fmt.Errorf("urkel/db/badger: cannot remove nodes in chunk mode")
	}

	ba.removedNodes = nodes
	return nil
}

func (ba *badgerBatch) Commit(root node.Root) error {
	if err := ba.db.sanityCheckNamespace(root.Namespace); err != nil {
		return err
	}
	if !root.Follows(&ba.oldRoot) {
		return api.ErrRootMustFollowOld
	}

	// Create a separate transaction for reading values. Note that since we are
	// not doing updates in the same transaction this could cause read/write
	// conflicts. We don't care about those due to our storage structure as all
	// writes would write the same or compatible values.
	tx := ba.db.db.NewTransaction(false)
	defer tx.Discard()

	// Make sure that the round that we try to commit into has not yet been
	// finalized.
	lastFinalizedRound, exists := ba.db.meta.getLastFinalizedRound()
	if exists && lastFinalizedRound >= root.Round {
		return api.ErrAlreadyFinalized
	}

	// Get previous round.
	prevRound, err := getPreviousRound(tx, root.Round)
	if err != nil {
		return err
	}

	// Create root with an empty next link.
	var emptyHash hash.Hash
	emptyHash.Empty()
	if err = ba.bat.Set(rootLinkKeyFmt.Encode(root.Round, &root.Hash, &emptyHash), []byte("")); err != nil {
		return errors.Wrap(err, "urkel/db/badger: set returned error")
	}

	if ba.chunk {
		// Skip most of metadata updates if we are just importing chunks.
		key := rootGcUpdatesKeyFmt.Encode(root.Round, &root.Hash)
		if err = ba.bat.Set(key, cbor.Marshal(rootGcUpdates{})); err != nil {
			return errors.Wrap(err, "urkel/db/badger: set returned error")
		}
		key = rootAddedNodesKeyFmt.Encode(root.Round, &root.Hash)
		if err = ba.bat.Set(key, cbor.Marshal(rootAddedNodes{})); err != nil {
			return errors.Wrap(err, "urkel/db/badger: set returned error")
		}
	} else {
		// Update the root link for the old root.
		if !ba.oldRoot.Hash.IsEmpty() {
			if prevRound != ba.oldRoot.Round && ba.oldRoot.Round != root.Round {
				return api.ErrPreviousRoundMismatch
			}

			key := rootLinkKeyFmt.Encode(ba.oldRoot.Round, &ba.oldRoot.Hash, &emptyHash)
			_, err = tx.Get(key)
			switch err {
			case nil:
			case badger.ErrKeyNotFound:
				return api.ErrRootNotFound
			default:
				return err
			}

			key = rootLinkKeyFmt.Encode(ba.oldRoot.Round, &ba.oldRoot.Hash, &root.Hash)
			if err = ba.bat.Set(key, []byte("")); err != nil {
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
		key := rootGcUpdatesKeyFmt.Encode(root.Round, &root.Hash)
		if err = ba.bat.Set(key, cbor.Marshal(gcUpdates)); err != nil {
			return errors.Wrap(err, "urkel/db/badger: set returned error")
		}

		// Store added nodes (only needed until the round is finalized).
		key = rootAddedNodesKeyFmt.Encode(root.Round, &root.Hash)
		if err = ba.bat.Set(key, cbor.Marshal(ba.addedNodes)); err != nil {
			return errors.Wrap(err, "urkel/db/badger: set returned error")
		}

		// Store write log.
		if ba.writeLog != nil && ba.annotations != nil {
			log := api.MakeHashedDBWriteLog(ba.writeLog, ba.annotations)
			bytes := cbor.Marshal(log)
			key := writeLogKeyFmt.Encode(root.Round, &root.Hash, &ba.oldRoot.Hash)
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
	if err = s.batch.bat.Set(nodeKeyFmt.Encode(&h), data); err != nil {
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
