// Package badger provides a Badger-backed node database.
package badger

import (
	"context"
	"fmt"
	"sync"

	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const dbVersion = 3

var (
	// nodeKeyFmt is the key format for nodes (node hash).
	//
	// Value is serialized node.
	nodeKeyFmt = keyformat.New(0x00, &hash.Hash{})
	// writeLogKeyFmt is the key format for write logs (version, new root,
	// old root).
	//
	// Value is CBOR-serialized write log.
	writeLogKeyFmt = keyformat.New(0x01, uint64(0), &hash.Hash{}, &hash.Hash{})
	// rootsMetadataKeyFmt is the key format for roots metadata. The key format is (version).
	//
	// Value is CBOR-serialized rootsMetadata.
	rootsMetadataKeyFmt = keyformat.New(0x02, uint64(0))
	// rootUpdatedNodesKeyFmt is the key format for the pending updated nodes for the
	// given root that need to be removed only in case the given root is not among
	// the finalized roots. They key format is (version, root).
	//
	// Value is CBOR-serialized []updatedNode.
	rootUpdatedNodesKeyFmt = keyformat.New(0x03, uint64(0), &hash.Hash{})
	// metadataKeyFmt is the key format for metadata.
	//
	// Value is CBOR-serialized metadata.
	metadataKeyFmt = keyformat.New(0x04)
)

// New creates a new BadgerDB-backed node database.
func New(cfg *api.Config) (api.NodeDB, error) {
	db := &badgerNodeDB{
		logger:           logging.GetLogger("mkvs/db/badger"),
		namespace:        cfg.Namespace,
		readOnly:         cfg.ReadOnly,
		discardWriteLogs: cfg.DiscardWriteLogs,
	}

	opts := badger.DefaultOptions(cfg.DB)
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(db.logger))
	opts = opts.WithSyncWrites(!cfg.NoFsync)
	// Allow value log truncation if required (this is needed to recover the
	// value log file which can get corrupted in crashes).
	opts = opts.WithTruncate(true)
	opts = opts.WithCompression(options.Snappy)
	opts = opts.WithBlockCacheSize(cfg.MaxCacheSize)
	opts = opts.WithReadOnly(cfg.ReadOnly)
	opts = opts.WithDetectConflicts(false)

	if cfg.MemoryOnly {
		db.logger.Warn("using memory-only mode, data will not be persisted")
		opts = opts.WithInMemory(true).WithDir("").WithValueDir("")
	}

	var err error
	if db.db, err = badger.OpenManaged(opts); err != nil {
		return nil, fmt.Errorf("mkvs/badger: failed to open database: %w", err)
	}

	// Make sure that we can discard any deleted/invalid metadata.
	db.db.SetDiscardTs(tsMetadata)

	// Load database metadata.
	if err = db.load(); err != nil {
		_ = db.db.Close()
		return nil, fmt.Errorf("mkvs/badger: failed to load metadata: %w", err)
	}

	db.gc = cmnBadger.NewGCWorker(db.logger, db.db)

	return db, nil
}

type badgerNodeDB struct { // nolint: maligned
	logger *logging.Logger

	namespace common.Namespace

	readOnly         bool
	discardWriteLogs bool

	db *badger.DB
	gc *cmnBadger.GCWorker

	// metaUpdateLock must be held at any point where data at tsMetadata is read and updated. This
	// is required because all metadata updates happen at the same timestamp and as such conflicts
	// cannot be detected.
	metaUpdateLock sync.Mutex
	meta           metadata

	closeOnce sync.Once
}

func (d *badgerNodeDB) load() error {
	tx := d.db.NewTransactionAt(tsMetadata, true)
	defer tx.Discard()

	// Load metadata.
	item, err := tx.Get(metadataKeyFmt.Encode())
	switch err {
	case nil:
		// Metadata already exists, just load it and verify that it is
		// compatible with what we have here.
		err = item.Value(func(data []byte) error {
			return cbor.UnmarshalTrusted(data, &d.meta.value)
		})
		if err != nil {
			return err
		}

		if d.meta.value.Version != dbVersion {
			return fmt.Errorf("incompatible database version (expected: %d got: %d)",
				dbVersion,
				d.meta.value.Version,
			)
		}
		if !d.meta.value.Namespace.Equal(&d.namespace) {
			return fmt.Errorf("incompatible namespace (expected: %s got: %s)",
				d.namespace,
				d.meta.value.Namespace,
			)
		}
	case badger.ErrKeyNotFound:
	default:
		return err
	}

	// No metadata exists, create some.
	d.meta.value.Version = dbVersion
	d.meta.value.Namespace = d.namespace
	if err = d.meta.save(tx); err != nil {
		return err
	}

	return tx.CommitAt(tsMetadata, nil)
}

func (d *badgerNodeDB) sanityCheckNamespace(ns common.Namespace) error {
	if !ns.Equal(&d.namespace) {
		return api.ErrBadNamespace
	}
	return nil
}

func (d *badgerNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("mkvs/badger: attempted to get invalid pointer from node database")
	}
	if err := d.sanityCheckNamespace(root.Namespace); err != nil {
		return nil, err
	}
	// If the version is earlier than the earliest version, we don't have the node (it was pruned).
	// Note that the key can still be present in the database until it gets compacted.
	if root.Version < d.meta.getEarliestVersion() {
		return nil, api.ErrNodeNotFound
	}

	tx := d.db.NewTransactionAt(versionToTs(root.Version), false)
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
		return nil, fmt.Errorf("mkvs/badger: failed to Get node from backing store: %w", err)
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
		return nil, fmt.Errorf("mkvs/badger: failed to unmarshal node: %w", err)
	}

	return n, nil
}

func (d *badgerNodeDB) GetWriteLog(ctx context.Context, startRoot, endRoot node.Root) (writelog.Iterator, error) {
	if d.discardWriteLogs {
		return nil, api.ErrWriteLogNotFound
	}
	if !endRoot.Follows(&startRoot) {
		return nil, api.ErrRootMustFollowOld
	}
	if err := d.sanityCheckNamespace(startRoot.Namespace); err != nil {
		return nil, err
	}
	// If the version is earlier than the earliest version, we don't have the roots.
	if endRoot.Version < d.meta.getEarliestVersion() {
		return nil, api.ErrWriteLogNotFound
	}

	tx := d.db.NewTransactionAt(versionToTs(endRoot.Version), false)
	discardTx := true
	defer func() {
		if discardTx {
			tx.Discard()
		}
	}()

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
	queue := []*wlItem{{depth: 0, endRootHash: endRoot.Hash}}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		curItem := queue[0]
		queue = queue[1:]

		wl, err := func() (writelog.Iterator, error) {
			// Iterate over all write logs that result in the current item.
			prefix := writeLogKeyFmt.Encode(endRoot.Version, &curItem.endRootHash)
			it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
			defer it.Close()

			for it.Rewind(); it.Valid(); it.Next() {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}

				item := it.Item()

				var decVersion uint64
				var decEndRootHash hash.Hash
				var decStartRootHash hash.Hash

				if !writeLogKeyFmt.Decode(item.Key(), &decVersion, &decEndRootHash, &decStartRootHash) {
					// This should not happen as the Badger iterator should take care of it.
					panic("mkvs/badger: bad iterator")
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
					discardTx = false
					// Close iterator now as ReviveHashedDBWriteLogs can close the txn immediately.
					it.Close()
					return api.ReviveHashedDBWriteLogs(ctx,
						func() (node.Root, api.HashedDBWriteLog, error) {
							if index >= len(nextItem.logKeys) {
								return node.Root{}, nil, nil
							}

							key := nextItem.logKeys[index]
							root := node.Root{
								Namespace: endRoot.Namespace,
								Version:   endRoot.Version,
								Hash:      nextItem.logRoots[index],
							}

							item, err := tx.Get(key)
							if err != nil {
								return node.Root{}, nil, err
							}

							var log api.HashedDBWriteLog
							err = item.Value(func(data []byte) error {
								return cbor.UnmarshalTrusted(data, &log)
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
							tx.Discard()
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

func (d *badgerNodeDB) GetLatestVersion(ctx context.Context) (uint64, error) {
	version, _ := d.meta.getLastFinalizedVersion()
	return version, nil
}

func (d *badgerNodeDB) GetEarliestVersion(ctx context.Context) (uint64, error) {
	return d.meta.getEarliestVersion(), nil
}

func (d *badgerNodeDB) GetRootsForVersion(ctx context.Context, version uint64) (roots []hash.Hash, err error) {
	// If the version is earlier than the earliest version, we don't have the roots.
	if version < d.meta.getEarliestVersion() {
		return nil, nil
	}

	tx := d.db.NewTransactionAt(tsMetadata, false)
	defer tx.Discard()

	rootsMeta, err := loadRootsMetadata(tx, version)
	if err != nil {
		return nil, err
	}

	for rootHash := range rootsMeta.Roots {
		roots = append(roots, rootHash)
	}
	return
}

func (d *badgerNodeDB) HasRoot(root node.Root) bool {
	if err := d.sanityCheckNamespace(root.Namespace); err != nil {
		return false
	}

	// An empty root is always implicitly present.
	if root.Hash.IsEmpty() {
		return true
	}

	// If the version is earlier than the earliest version, we don't have the root.
	if root.Version < d.meta.getEarliestVersion() {
		return false
	}

	var emptyHash hash.Hash
	emptyHash.Empty()

	tx := d.db.NewTransactionAt(tsMetadata, false)
	defer tx.Discard()

	rootsMeta, err := loadRootsMetadata(tx, root.Version)
	if err != nil {
		panic(err)
	}
	return rootsMeta.Roots[root.Hash] != nil
}

func (d *badgerNodeDB) Finalize(ctx context.Context, version uint64, roots []hash.Hash) error { // nolint: gocyclo
	if d.readOnly {
		return api.ErrReadOnly
	}

	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	// Version batch collects removals at the version timestamp.
	versionBatch := d.db.NewWriteBatchAt(versionToTs(version))
	defer versionBatch.Cancel()
	// Transaction is used to read at the version timestamp.
	tx := d.db.NewTransactionAt(versionToTs(version), true)
	defer tx.Discard()

	// Make sure that the previous version has been finalized.
	lastFinalizedVersion, exists := d.meta.getLastFinalizedVersion()
	if version > 0 && exists && lastFinalizedVersion < (version-1) {
		return api.ErrNotFinalized
	}
	// Make sure that this version has not yet been finalized.
	if exists && version <= lastFinalizedVersion {
		return api.ErrAlreadyFinalized
	}

	// Determine a set of finalized roots. Finalization is transitive, so if
	// a parent root is finalized the child should be consider finalized too.
	finalizedRoots := make(map[hash.Hash]bool)
	for _, rootHash := range roots {
		finalizedRoots[rootHash] = true
	}

	var rootsChanged bool
	rootsMeta, err := loadRootsMetadata(tx, version)
	if err != nil {
		return err
	}

	for updated := true; updated; {
		updated = false

		for rootHash, derivedRoots := range rootsMeta.Roots {
			if len(derivedRoots) == 0 {
				continue
			}

			for _, nextRoot := range derivedRoots {
				if !finalizedRoots[rootHash] && finalizedRoots[nextRoot] {
					finalizedRoots[rootHash] = true
					updated = true
				}
			}
		}
	}

	// Go through all roots and prune them based on whether they are finalized or not.
	maybeLoneNodes := make(map[hash.Hash]bool)
	notLoneNodes := make(map[hash.Hash]bool)

	for rootHash := range rootsMeta.Roots {
		// TODO: Consider colocating updated nodes with the root metadata.
		rootUpdatedNodesKey := rootUpdatedNodesKeyFmt.Encode(version, &rootHash)

		// Load hashes of nodes added during this version for this root.
		item, err := tx.Get(rootUpdatedNodesKey)
		if err != nil {
			panic(fmt.Errorf("mkvs/badger: corrupted/missing root updated nodes index: %w", err))
		}

		var updatedNodes []updatedNode
		err = item.Value(func(data []byte) error {
			return cbor.UnmarshalTrusted(data, &updatedNodes)
		})
		if err != nil {
			panic(fmt.Errorf("mkvs/badger: corrupted root updated nodes index: %w", err))
		}

		if finalizedRoots[rootHash] {
			// Make sure not to remove any nodes shared with finalized roots.
			for _, n := range updatedNodes {
				if n.Removed {
					maybeLoneNodes[n.Hash] = true
				} else {
					notLoneNodes[n.Hash] = true
				}
			}
		} else {
			// Remove any non-finalized roots. It is safe to remove these nodes
			// as they can never be resurrected due to the version being part of the
			// node hash as long as we make sure that these nodes are not shared
			// with any finalized roots added in the same version.
			for _, n := range updatedNodes {
				if !n.Removed {
					maybeLoneNodes[n.Hash] = true
				}
			}

			delete(rootsMeta.Roots, rootHash)
			rootsChanged = true

			// Remove write logs for the non-finalized root.
			if !d.discardWriteLogs {
				if err = func() error {
					rootWriteLogsPrefix := writeLogKeyFmt.Encode(version, &rootHash)
					wit := tx.NewIterator(badger.IteratorOptions{Prefix: rootWriteLogsPrefix})
					defer wit.Close()

					for wit.Rewind(); wit.Valid(); wit.Next() {
						if err = versionBatch.Delete(wit.Item().KeyCopy(nil)); err != nil {
							return err
						}
					}
					return nil
				}(); err != nil {
					return err
				}
			}
		}

		// Set of updated nodes no longer needed after finalization.
		if err = tx.Delete(rootUpdatedNodesKey); err != nil {
			return err
		}
	}

	// Clean any lone nodes.
	for h := range maybeLoneNodes {
		if notLoneNodes[h] {
			continue
		}

		key := nodeKeyFmt.Encode(&h)
		if err := versionBatch.Delete(key); err != nil {
			return err
		}
	}

	// Commit batch.
	if err := versionBatch.Flush(); err != nil {
		return err
	}

	// Save roots metadata if changed.
	if rootsChanged {
		if err := rootsMeta.save(tx); err != nil {
			return fmt.Errorf("mkvs/badger: failed to save roots metadata: %w", err)
		}
	}

	// Update last finalized version.
	if err := d.meta.setLastFinalizedVersion(tx, version); err != nil {
		return fmt.Errorf("mkvs/badger: failed to set last finalized version: %w", err)
	}

	if err := tx.CommitAt(tsMetadata, nil); err != nil {
		return fmt.Errorf("mkvs/badger: failed to commit metadata: %w", err)
	}
	return nil
}

func (d *badgerNodeDB) Prune(ctx context.Context, version uint64) error {
	if d.readOnly {
		return api.ErrReadOnly
	}

	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	// Make sure that the version that we try to prune has been finalized.
	lastFinalizedVersion, exists := d.meta.getLastFinalizedVersion()
	if !exists || lastFinalizedVersion < version {
		return api.ErrNotFinalized
	}
	// Make sure that the version that we are trying to prune is the earliest version.
	if version != d.meta.getEarliestVersion() {
		return api.ErrNotEarliest
	}

	// Remove all roots in version.
	batch := d.db.NewWriteBatchAt(versionToTs(version))
	defer batch.Cancel()
	tx := d.db.NewTransactionAt(versionToTs(version), true)
	defer tx.Discard()

	rootsMeta, err := loadRootsMetadata(tx, version)
	if err != nil {
		return err
	}

	maybeLoneRoots := make(map[hash.Hash]bool)
	for rootHash, derivedRoots := range rootsMeta.Roots {
		if len(derivedRoots) == 0 {
			// Need to only set the flag iff the flag has not already been set
			// to either value before.
			if _, ok := maybeLoneRoots[rootHash]; !ok {
				maybeLoneRoots[rootHash] = true
			}
		} else {
			maybeLoneRoots[rootHash] = false
		}
	}
	for rootHash, isLone := range maybeLoneRoots {
		if !isLone {
			continue
		}

		// Traverse the root and prune all items created in this version.
		root := node.Root{Namespace: d.namespace, Version: version, Hash: rootHash}
		var innerErr error
		err := api.Visit(ctx, d, root, func(ctx context.Context, n node.Node) bool {
			if n.GetCreatedVersion() == version {
				h := n.GetHash()
				if innerErr = batch.Delete(nodeKeyFmt.Encode(&h)); innerErr != nil {
					return false
				}
			}
			return true
		})
		if innerErr != nil {
			return innerErr
		}
		if err != nil {
			return err
		}
	}

	// Delete roots metadata.
	if err := tx.Delete(rootsMetadataKeyFmt.Encode(version)); err != nil {
		return fmt.Errorf("mkvs/badger: failed to remove roots metadata: %w", err)
	}

	// Prune all write logs in version.
	if !d.discardWriteLogs {
		wtx := d.db.NewTransactionAt(versionToTs(version), false)
		defer wtx.Discard()

		prefix := writeLogKeyFmt.Encode(version)
		it := wtx.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			if err := batch.Delete(it.Item().KeyCopy(nil)); err != nil {
				return err
			}
		}
	}

	// Commit batch.
	if err := batch.Flush(); err != nil {
		return fmt.Errorf("mkvs/badger: failed to flush batch: %w", err)
	}

	// Update metadata.
	if err := d.meta.setEarliestVersion(tx, version+1); err != nil {
		return fmt.Errorf("mkvs/badger: failed to set earliest version: %w", err)
	}
	if err := tx.CommitAt(tsMetadata, nil); err != nil {
		return fmt.Errorf("mkvs/badger: failed to commit: %w", err)
	}

	// Discard everything invalidated at or below given version.
	d.db.SetDiscardTs(versionToTs(version + 1))

	return nil
}

func (d *badgerNodeDB) NewBatch(oldRoot node.Root, version uint64, chunk bool) api.Batch {
	// WARNING: There is a maximum batch size and maximum batch entry count.
	// Both of these things are derived from the MaxTableSize option.
	//
	// The size limit also applies to normal transactions, so the "right"
	// thing to do would be to either crank up MaxTableSize or maybe split
	// the transaction out.

	return &badgerBatch{
		db:      d,
		bat:     d.db.NewWriteBatchAt(versionToTs(version)),
		oldRoot: oldRoot,
		chunk:   chunk,
	}
}

func (d *badgerNodeDB) Size() (int64, error) {
	lsm, vlog := d.db.Size()
	return lsm + vlog, nil
}

func (d *badgerNodeDB) Sync() error {
	return d.db.Sync()
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

type badgerBatch struct {
	api.BaseBatch

	db  *badgerNodeDB
	bat *badger.WriteBatch

	oldRoot node.Root
	chunk   bool

	writeLog     writelog.WriteLog
	annotations  writelog.Annotations
	updatedNodes []updatedNode
}

func (ba *badgerBatch) MaybeStartSubtree(subtree api.Subtree, depth node.Depth, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &badgerSubtree{batch: ba}
	}
	return subtree
}

func (ba *badgerBatch) PutWriteLog(writeLog writelog.WriteLog, annotations writelog.Annotations) error {
	if ba.chunk {
		return fmt.Errorf("mkvs/badger: cannot put write log in chunk mode")
	}
	if ba.db.discardWriteLogs {
		return nil
	}

	ba.writeLog = writeLog
	ba.annotations = annotations
	return nil
}

func (ba *badgerBatch) RemoveNodes(nodes []node.Node) error {
	if ba.chunk {
		return fmt.Errorf("mkvs/badger: cannot remove nodes in chunk mode")
	}

	for _, n := range nodes {
		ba.updatedNodes = append(ba.updatedNodes, updatedNode{
			Removed: true,
			Hash:    n.GetHash(),
		})
	}
	return nil
}

func (ba *badgerBatch) Commit(root node.Root) error {
	// XXX: Ideally this would fail at batch creation.
	if ba.db.readOnly {
		return api.ErrReadOnly
	}

	ba.db.metaUpdateLock.Lock()
	defer ba.db.metaUpdateLock.Unlock()

	if err := ba.db.sanityCheckNamespace(root.Namespace); err != nil {
		return err
	}
	if !root.Follows(&ba.oldRoot) {
		return api.ErrRootMustFollowOld
	}

	// Make sure that the version that we try to commit into has not yet been finalized.
	lastFinalizedVersion, exists := ba.db.meta.getLastFinalizedVersion()
	if exists && lastFinalizedVersion >= root.Version {
		return api.ErrAlreadyFinalized
	}

	// Update the set of roots for this version.
	tx := ba.db.db.NewTransactionAt(versionToTs(root.Version), true)
	defer tx.Discard()

	rootsMeta, err := loadRootsMetadata(tx, root.Version)
	if err != nil {
		return err
	}

	if rootsMeta.Roots[root.Hash] != nil {
		// Root already exists, no need to do anything since if the hash matches, everything will
		// be identical and we would just be duplicating work.
		//
		// If we are importing a chunk, there can be multiple commits for the same root.
		if !ba.chunk {
			ba.Reset()
			return ba.BaseBatch.Commit(root)
		}
	} else {
		// Create root with no derived roots.
		rootsMeta.Roots[root.Hash] = []hash.Hash{}

		if err = rootsMeta.save(tx); err != nil {
			return fmt.Errorf("mkvs/badger: failed to save roots metadata: %w", err)
		}
	}

	if ba.chunk {
		// Skip most of metadata updates if we are just importing chunks.
		key := rootUpdatedNodesKeyFmt.Encode(root.Version, &root.Hash)
		if err = tx.Set(key, cbor.Marshal([]updatedNode{})); err != nil {
			return fmt.Errorf("mkvs/badger: set returned error: %w", err)
		}
	} else {
		// Update the root link for the old root.
		if !ba.oldRoot.Hash.IsEmpty() {
			if ba.oldRoot.Version < ba.db.meta.getEarliestVersion() && ba.oldRoot.Version != root.Version {
				return api.ErrPreviousVersionMismatch
			}

			var oldRootsMeta *rootsMetadata
			oldRootsMeta, err = loadRootsMetadata(tx, ba.oldRoot.Version)
			if err != nil {
				return err
			}

			if _, ok := oldRootsMeta.Roots[ba.oldRoot.Hash]; !ok {
				return api.ErrRootNotFound
			}

			oldRootsMeta.Roots[ba.oldRoot.Hash] = append(oldRootsMeta.Roots[ba.oldRoot.Hash], root.Hash)
			if err = oldRootsMeta.save(tx); err != nil {
				return fmt.Errorf("mkvs/badger: failed to save old roots metadata: %w", err)
			}
		}

		// Store updated nodes (only needed until the version is finalized).
		key := rootUpdatedNodesKeyFmt.Encode(root.Version, &root.Hash)
		if err = tx.Set(key, cbor.Marshal(ba.updatedNodes)); err != nil {
			return fmt.Errorf("mkvs/badger: set returned error: %w", err)
		}

		// Store write log.
		if ba.writeLog != nil && ba.annotations != nil {
			log := api.MakeHashedDBWriteLog(ba.writeLog, ba.annotations)
			bytes := cbor.Marshal(log)
			key := writeLogKeyFmt.Encode(root.Version, &root.Hash, &ba.oldRoot.Hash)
			if err = ba.bat.Set(key, bytes); err != nil {
				return fmt.Errorf("mkvs/badger: set new write log returned error: %w", err)
			}
		}
	}

	// Flush node updates.
	if err = ba.bat.Flush(); err != nil {
		return fmt.Errorf("mkvs/badger: failed to flush batch: %w", err)
	}

	// Commit root metadata updates. This is done last, so in case we fail, we can still retry.
	if err = tx.CommitAt(tsMetadata, nil); err != nil {
		return err
	}

	ba.writeLog = nil
	ba.annotations = nil
	ba.updatedNodes = nil

	return ba.BaseBatch.Commit(root)
}

func (ba *badgerBatch) Reset() {
	ba.bat.Cancel()
	ba.writeLog = nil
	ba.annotations = nil
	ba.updatedNodes = nil
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
	s.batch.updatedNodes = append(s.batch.updatedNodes, updatedNode{Hash: h})
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
