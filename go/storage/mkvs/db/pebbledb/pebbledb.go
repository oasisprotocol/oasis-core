// Package pebbledb provides a PebbleDB-backed node database.
package pebbledb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const (
	dbVersion = 1
	// multipartVersionNone is the value used for the multipart version in metadata
	// when no multipart restore is in progress.
	multipartVersionNone uint64 = 0
)

// Non-versioned keys.
var (
	// rootUpdatedNodesKeyFmt is the key format for the pending updated nodes for the
	// given root that need to be removed only in case the given root is not among
	// the finalized roots. They key format is (version, root).
	//
	// Value is CBOR-serialized []updatedNode.
	rootUpdatedNodesKeyFmt = keyformat.New(0x00, uint64(0), &node.TypedHash{})

	// metadataKeyFmt is the key format for metadata.
	//
	// Value is CBOR-serialized metadata.
	metadataKeyFmt = keyformat.New(0x01)

	// rootsMetadataKeyFmt is the key format for roots metadata. The key format is (version).
	//
	// Values is CBOR-serialized rootsMetadata.
	rootsMetadataKeyFmt = keyformat.New(0x02, uint64(0))

	// multipartRestoreNodeLogKeyFmt is the key format for the nodes inserted during a chunk restore.
	// Once a set of chunks is fully restored, these entries should be removed. If chunk restoration
	// is interrupted for any reason, the nodes associated with these keys should be removed, along
	// with these entries.
	//
	// Value is empty.
	multipartRestoreNodeLogKeyFmt = keyformat.New(0x03, &node.TypedHash{})

	// multipartRestoreNodeLogKeyFmt is the key format for the root nodes inserted during a chunk restore.
	// Once a set of chunks is fully restored, these entries should be removed. If chunk restoration
	// is interrupted for any reason, the nodes associated with these keys should be removed, along
	// with these entries.
	//
	// Value is empty.
	multipartRestoreRootLogKeyFmt = keyformat.New(0x04, &node.TypedHash{})
)

// Timestamped (versioned) keys.
var (
	// nodeKeyFmt is the key format for nodes (node hash).
	//
	// Value is serialized node.
	nodeMVCCKeyFmt = keyformat.New(mvccKeyIndicator+1, &hash.Hash{})

	// writeLogKeyFmt is the key format for write logs (version, new root,
	// old root).
	//
	// Value is CBOR-serialized write log.
	writeLogMVCCKeyFmt = keyformat.New(mvccKeyIndicator+2, uint64(0), &node.TypedHash{}, &node.TypedHash{})

	// rootNodeKeyFmt is the key format for root nodes (node hash).
	//
	// Value is empty.
	rootNodeMVCCKeyFmt = keyformat.New(mvccKeyIndicator+3, &node.TypedHash{})
)

func New(cfg *api.Config) (api.NodeDB, error) {
	// TODO: Could try optimizing some options, e.g.:
	// https://github.com/ethereum/go-ethereum/blob/16ce7bf50fa71c907d1dc6504ed32a9161e71351/ethdb/pebble/pebble.go#L181-L222
	// https://github.com/bnb-chain/bsc/blob/c6aeee20016181a5ad4153acbbbf2cf1b27be0a5/ethdb/pebble/pebble.go#L178-L227
	// https://github.com/cockroachdb/pebble/blob/291a41df6aeb6f0455579af6372c2545794c254e/cmd/pebble/db.go#L55-L91
	opts := &pebble.Options{
		Comparer: MVCCComparer,
		ReadOnly: cfg.ReadOnly,
		Logger:   newPebbleLogger("storage/mkvs/pebbledb"),
		// Use all available CPUs for faster compaction.
		MaxConcurrentCompactions: func() int { return runtime.NumCPU() },

		// https://github.com/cockroachdb/pebble/blob/291a41df6aeb6f0455579af6372c2545794c254e/cmd/pebble/db.go#L55-L91
		FormatMajorVersion:          pebble.FormatNewest,
		Levels:                      make([]pebble.LevelOptions, 7),
		MaxOpenFiles:                16384,
		MemTableSize:                64 << 20,
		MemTableStopWritesThreshold: 4,
	}
	for i := 0; i < len(opts.Levels); i++ {
		l := &opts.Levels[i]
		l.BlockSize = 32 << 10       // 32 KB
		l.IndexBlockSize = 256 << 10 // 256 KB
		l.FilterPolicy = bloom.FilterPolicy(10)
		l.FilterType = pebble.TableFilter
		if i > 0 {
			l.TargetFileSize = opts.Levels[i-1].TargetFileSize * 2
		}
		l.EnsureDefaults()
	}
	opts.Levels[6].FilterPolicy = nil
	opts.FlushSplitBytes = opts.Levels[0].TargetFileSize

	if cfg.MaxCacheSize > 0 {
		opts.Cache = pebble.NewCache(cfg.MaxCacheSize)
	} else {
		opts.Cache = pebble.NewCache(1024 * 1024 * 1024) // 1GB.
	}

	opts = opts.EnsureDefaults()
	db, err := pebble.Open(cfg.DB, opts)
	if err != nil {
		return nil, fmt.Errorf("mkvs/pebbledb: failed to open database: %w", err)
	}

	pdb := &pebbleNodeDB{
		logger:           logging.GetLogger("storage/mkvs/pebbledb"),
		namespace:        cfg.Namespace,
		discardWriteLogs: cfg.DiscardWriteLogs,
		readOnly:         cfg.ReadOnly,
		db:               db,
		writeOptions: &pebble.WriteOptions{
			Sync: !cfg.NoFsync,
		},
	}
	if err = pdb.load(); err != nil {
		defer pdb.db.Close()
		return nil, err
	}

	return pdb, nil
}

type pebbleNodeDB struct {
	logger           *logging.Logger
	discardWriteLogs bool
	readOnly         bool

	namespace common.Namespace

	// metaUpdateLock must be held at any point where data at tsMetadata is read and updated. This
	// is required because all metadata updates happen at the same timestamp and as such conflicts
	// cannot be detected.
	metaUpdateLock   sync.Mutex
	meta             metadata
	multipartVersion uint64

	db           *pebble.DB
	writeOptions *pebble.WriteOptions

	closeOnce sync.Once
}

func (d *pebbleNodeDB) load() error {
	// Load metadata.
	item, closer, err := d.db.Get(metadataKeyFmt.Encode())
	switch {
	case err == nil:
		// Continue below.
		defer closer.Close()
	case errors.Is(err, pebble.ErrNotFound):
		// No metadata, initialize.
		d.meta.value.Version = dbVersion
		d.meta.value.Namespace = d.namespace
		if err = d.meta.save(d.db, d.writeOptions); err != nil {
			return err
		}
	default:
		return fmt.Errorf("mkvs/pebbledb: failed to get metadata: %w", err)
	}

	// Metadata already exists, just load it and verify that it is
	// compatible with what we have here.
	if err = cbor.UnmarshalTrusted(item, &d.meta.value); err != nil {
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

	return nil
}

func (d *pebbleNodeDB) sanityCheckNamespace(ns common.Namespace) error {
	if !ns.Equal(&d.namespace) {
		return api.ErrBadNamespace
	}
	return nil
}

func (d *pebbleNodeDB) checkRoot(root node.Root) error {
	rootHash := node.TypedHashFromRoot(root)

	err := existsVersioned(d.db, rootNodeMVCCKeyFmt.Encode(&rootHash), root.Version)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errVersionedNotFound):
		return api.ErrRootNotFound
	default:
		d.logger.Error("failed to check root existence",
			"err", err,
		)
		return fmt.Errorf("failed to check root existence: %w", err)
	}
}

// Implements api.NodeDB.
func (d *pebbleNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("mkvs/pebbledb: attempted to get invalid pointer from node database")
	}
	if err := d.sanityCheckNamespace(root.Namespace); err != nil {
		return nil, err
	}

	// If the version is earlier than the earliest version, we don't have the node (it was pruned).
	// Note that the key can still be present in the database until it gets compacted. // TODO: check this.
	if root.Version < d.meta.getEarliestVersion() {
		return nil, api.ErrNodeNotFound
	}

	// Check if the root actually exists.
	if err := d.checkRoot(root); err != nil {
		return nil, err
	}

	b, err := fetchVersionedRaw(d.db, nodeMVCCKeyFmt.Encode(&ptr.Hash), root.Version)
	switch {
	case err == nil:
		var n node.Node
		n, err = node.UnmarshalBinary(b)
		if err != nil {
			return nil, fmt.Errorf("mkvs/pebbledb: failed to unmarshal node: %w", err)
		}
		return n, nil
	case errors.Is(err, errVersionedNotFound):
		return nil, api.ErrNodeNotFound
	default:
		return nil, fmt.Errorf("mkvs/pebbledb: failed to get node from backing store: %w", err)
	}
}

// Implements api.NodeDB.
func (d *pebbleNodeDB) GetWriteLog(ctx context.Context, startRoot, endRoot node.Root) (writelog.Iterator, error) {
	if d.discardWriteLogs {
		return nil, api.ErrWriteLogNotFound
	}
	if !endRoot.Follows(&startRoot) {
		return nil, api.ErrRootMustFollowOld
	}
	// If the version is earlier than the earliest version, we don't have the roots.
	if err := d.sanityCheckNamespace(startRoot.Namespace); err != nil {
		return nil, err
	}

	// Check if the root actually exists.
	if err := d.checkRoot(endRoot); err != nil {
		return nil, err
	}

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
		endRootHash node.TypedHash
		logKeys     [][]byte
		logRoots    []node.TypedHash
	}
	// NOTE: We could use a proper deque, but as long as we keep the number of hops and
	//       forks low, this should not be a problem.
	queue := []*wlItem{{depth: 0, endRootHash: node.TypedHashFromRoot(endRoot)}}
	startRootHash := node.TypedHashFromRoot(startRoot)
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		curItem := queue[0]
		queue = queue[1:]

		wl, err := func() (writelog.Iterator, error) {
			// Iterate over all write logs that result in the current item.
			prefix := writeLogMVCCKeyFmt.Encode(endRoot.Version, &curItem.endRootHash)
			it := versionedIterator(d.db, prefix, endRoot.Version)
			defer it.Close()

			for ; it.Valid(); it.Next() {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}

				key := it.Key()

				var decVersion uint64
				var decEndRootHash node.TypedHash
				var decStartRootHash node.TypedHash
				if !writeLogMVCCKeyFmt.Decode(key, &decVersion, &decEndRootHash, &decStartRootHash) {
					return nil, nil
				}

				nextItem := wlItem{
					depth:       curItem.depth + 1,
					endRootHash: decStartRootHash,
					// Only store log keys to avoid keeping everything in memory while
					// we are searching for the right path.
					logKeys:  append(curItem.logKeys, key),
					logRoots: append(curItem.logRoots, curItem.endRootHash),
				}
				if nextItem.endRootHash.Equal(&startRootHash) {
					// Path has been found, deserialize and stream write logs.
					var index int
					return api.ReviveHashedDBWriteLogs(ctx,
						func() (node.Root, api.HashedDBWriteLog, error) {
							if index >= len(nextItem.logKeys) {
								return node.Root{}, nil, nil
							}

							key := nextItem.logKeys[index]
							root := node.Root{
								Namespace: endRoot.Namespace,
								Version:   endRoot.Version,
								Type:      nextItem.logRoots[index].Type(),
								Hash:      nextItem.logRoots[index].Hash(),
							}

							// TODO: ensure db not closed?

							var log api.HashedDBWriteLog
							err := fetchVersioned(d.db, key, endRoot.Version, &log)
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

func (d *pebbleNodeDB) GetLatestVersion() (uint64, bool) {
	return d.meta.getLastFinalizedVersion()
}

func (d *pebbleNodeDB) GetEarliestVersion() uint64 {
	return d.meta.getEarliestVersion()
}

func (d *pebbleNodeDB) GetRootsForVersion(version uint64) ([]node.Root, error) {
	// If the version is earlier than the earliest version, we don't have the roots.
	if version < d.meta.getEarliestVersion() {
		return nil, nil
	}

	rootsMeta, err := loadRootsMetadata(d.db, version)
	if err != nil {
		return nil, err
	}

	roots := make([]node.Root, 0, len(rootsMeta.Roots))
	for rootHash := range rootsMeta.Roots {
		roots = append(roots, node.Root{
			Namespace: d.namespace,
			Version:   version,
			Type:      rootHash.Type(),
			Hash:      rootHash.Hash(),
		})
	}
	return roots, nil
}

func (d *pebbleNodeDB) HasRoot(root node.Root) bool {
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

	rootsMeta, err := loadRootsMetadata(d.db, root.Version)
	if err != nil {
		panic(err)
	}

	_, exists := rootsMeta.Roots[node.TypedHashFromRoot(root)]
	return exists
}

func (d *pebbleNodeDB) Finalize(roots []node.Root) error { // nolint: gocyclo
	if len(roots) == 0 {
		return fmt.Errorf("mkvs/pebbledb: need at least one root to finalize")
	}
	version := roots[0].Version

	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	if d.multipartVersion != multipartVersionNone && d.multipartVersion != version {
		return api.ErrInvalidMultipartVersion
	}

	// Make sure that the previous version has been finalized (if we are not restoring).
	lastFinalizedVersion, exists := d.meta.getLastFinalizedVersion()
	if d.multipartVersion == multipartVersionNone && version > 0 && exists && lastFinalizedVersion < (version-1) {
		return api.ErrNotFinalized
	}
	// Make sure that this version has not yet been finalized.
	if exists && version <= lastFinalizedVersion {
		return api.ErrAlreadyFinalized
	}

	// Determine the set of finalized roots. Finalization is transitive, so if
	// a parent root is finalized the child should be considered finalized too.
	finalizedRoots := make(map[node.TypedHash]bool)
	for _, root := range roots {
		if root.Version != version {
			return fmt.Errorf("mkvs/rocksdb: roots to finalize don't have matching versions")
		}
		finalizedRoots[node.TypedHashFromRoot(root)] = true
	}
	var rootsChanged bool
	rootsMeta, err := loadRootsMetadata(d.db, version)
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

	// Sanity check the input roots list.
	for iroot := range finalizedRoots {
		h := iroot.Hash()
		if _, ok := rootsMeta.Roots[iroot]; !ok && !h.IsEmpty() {
			return api.ErrRootNotFound
		}
	}

	batch := d.db.NewBatch()
	defer batch.Close()

	// Go through all roots and prune them based on whether they are finalized or not.
	maybeLoneNodes := make(map[hash.Hash]node.RootType)
	notLoneNodes := make(map[hash.Hash]node.RootType)

	for rootHash := range rootsMeta.Roots {
		// TODO: Consider colocating updated nodes with the root metadata.
		rootUpdatedNodesKey := rootUpdatedNodesKeyFmt.Encode(version, &rootHash)

		// Load hashes of nodes added during this version for this root.
		var updatedNodes []updatedNode
		var data []byte
		var closer io.Closer
		data, closer, err = d.db.Get(rootUpdatedNodesKey)
		switch {
		case err == nil:
			defer closer.Close()
			if err = cbor.Unmarshal(data, &updatedNodes); err != nil {
				panic(fmt.Errorf("mkvs/pebbledb: corrupted root updated nodes index: %w", err))
			}
			// Continues below.
		case errors.Is(err, errVersionedNotFound):
			panic(fmt.Errorf("mkvs/pebbledb: missing root updated nodes index"))
		default:
			panic(fmt.Errorf("mkvs/pebbledb: corrupted root updated nodes index: %w", err))
		}

		if finalizedRoots[rootHash] {
			// Make sure not to remove any nodes shared with finalized roots.
			for _, n := range updatedNodes {
				if n.Removed {
					maybeLoneNodes[n.Hash] = rootHash.Type()
				} else {
					notLoneNodes[n.Hash] = rootHash.Type()
				}
			}
		} else {
			// Remove any non-finalized roots. It is safe to remove these nodes as MVSS version
			// control will make sure they are not removed if they are resurrected in any later
			// version as long as we make sure that these nodes are not shared with any finalized
			// roots added in the same version.
			for _, n := range updatedNodes {
				if !n.Removed {
					maybeLoneNodes[n.Hash] = rootHash.Type()
				}
			}

			delete(rootsMeta.Roots, rootHash)
			rootsChanged = true

			// Remove write logs for the non-finalized root.
			if !d.discardWriteLogs {
				if err = func() error {
					rootWriteLogsPrefix := writeLogMVCCKeyFmt.Encode(version, &rootHash)
					wit := versionedIterator(d.db, rootWriteLogsPrefix, version)
					defer wit.Close()

					for ; wit.Valid(); wit.Next() {
						// Delete versioned key.
						if err = deleteVersioned(batch, wit.Key(), version); err != nil {
							return fmt.Errorf("mkvs/pebbledb: failed to delete write log: %w", err)
						}
					}
					return nil
				}(); err != nil {
					return err
				}
			}
		}

		// Set of updated nodes no longer needed after finalization.
		if err = batch.Delete(rootUpdatedNodesKey, d.writeOptions); err != nil {
			return err
		}
	}
	// Clean any lone nodes.
	for h := range maybeLoneNodes {
		if _, ok := notLoneNodes[h]; ok {
			continue
		}
		if err = deleteVersioned(batch, nodeMVCCKeyFmt.Encode(&h), version); err != nil {
			return err
		}
	}

	// Save roots metadata if changed.
	if rootsChanged {
		if err = rootsMeta.save(batch); err != nil {
			return err
		}
	}

	// Update last finalized version.
	if err := d.meta.setLastFinalizedVersion(batch, version); err != nil {
		return err
	}

	// Commit batch.
	if err := d.db.Apply(batch, d.writeOptions); err != nil {
		return fmt.Errorf("mkvs/pebbledb: failed to commit finalized roots: %w", err)
	}

	// Clean multipart metadata if there is any.
	if d.multipartVersion != multipartVersionNone {
		if err := d.cleanMultipartLocked(false); err != nil {
			return err
		}
	}
	return nil
}

func (d *pebbleNodeDB) Prune(_ context.Context, version uint64) error {
	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	if d.multipartVersion != multipartVersionNone {
		return api.ErrMultipartInProgress
	}

	// Make sure that the version that we try to prune has been finalized.
	lastFinalizedVersion, exists := d.meta.getLastFinalizedVersion()
	if !exists || lastFinalizedVersion < version {
		return api.ErrNotFinalized
	}
	// Make sure that the version that we are trying to prune is the earliest version.
	if version != d.meta.getEarliestVersion() {
		return api.ErrNotEarliest
	}

	_, err := loadRootsMetadata(d.db, version)
	if err != nil {
		return err
	}

	batch := d.db.NewBatch()
	defer batch.Close()

	// Handle prunning of all MVCC keys.
	iter, _ := d.db.NewIter(&pebble.IterOptions{LowerBound: []byte{0x80}})
	defer iter.Close()

	var prevFullKey []byte
	var prevKey []byte
	var prevVersion uint64
	var prevIsTombstone bool

	for iter.First(); iter.Valid(); {
		key, verRaw, ok := decodeMVCCKey(iter.Key())
		if !ok {
			return fmt.Errorf("mkvs/pebbledb: invalid key while prunning: %s", iter.Key())
		}
		var keyVersion uint64
		keyVersion, err = decodeVersion(verRaw)
		if err != nil {
			return fmt.Errorf("mkvs/pebbledb: failed to decode key version: %w", err)
		}

		// Smallest key version is greater than the version we are prunning.
		// Skip this key entirely.
		if keyVersion > version {
			iter.NextPrefix()
			continue
		}

		// Delete the key if:
		// There is an entry with a larger version, which is also <= prune height,
		// or the key has been tombstoned and its version <= prune height.
		if bytes.Equal(prevKey, key) && (prevVersion <= version || prevIsTombstone) {
			if err = batch.Delete(prevFullKey, nil); err != nil {
				return err
			}
		}

		// Update previous key values.
		prevKey = key
		prevFullKey = slices.Clone(iter.Key())
		prevVersion = keyVersion
		prevIsTombstone = mvccIsTombstone(iter.Value())

		// Move to the next key (possible next version of the same key).
		iter.Next()
	}

	// Prune roots metadata.
	if err = batch.Delete(rootsMetadataKeyFmt.Encode(version), nil); err != nil {
		return fmt.Errorf("mkvs/pebbledb: failed to prune roots metadata: %w", err)
	}

	// Update metadata.
	d.meta.setEarliestVersion(batch, version+1)

	// TODO: commit smaller batches.
	if err = d.db.Apply(batch, d.writeOptions); err != nil {
		return fmt.Errorf("mkvs/pebbledb: failed to apply prune batch: %w", err)
	}

	return nil
}

func (d *pebbleNodeDB) StartMultipartInsert(version uint64) error {
	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	if version == multipartVersionNone {
		return api.ErrInvalidMultipartVersion
	}

	if d.multipartVersion != multipartVersionNone {
		if d.multipartVersion != version {
			return api.ErrMultipartInProgress
		}
		// Multipart already initialized at the same version, so this was
		// probably called e.g. as part of a further checkpoint restore.
		return nil
	}

	if err := d.meta.setMultipartVersion(d.db, version, d.writeOptions); err != nil {
		return err
	}
	d.multipartVersion = version

	return nil
}

func (d *pebbleNodeDB) AbortMultipartInsert() error {
	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	return d.cleanMultipartLocked(true)
}

// Assumes metaUpdateLock is held when called.
func (d *pebbleNodeDB) cleanMultipartLocked(removeNodes bool) error {
	var version uint64

	if d.multipartVersion != multipartVersionNone {
		version = d.multipartVersion
	} else {
		version = d.meta.getMultipartVersion()
	}
	if version == multipartVersionNone {
		// No multipart in progress, but it's not an error to call in a situation like this.
		return nil
	}

	batch := d.db.NewBatch()
	defer batch.Close()
	var logged bool

	// Clean up the node log.
	cleanNodes := func(keyFormat *keyformat.KeyFormat, isRoot bool) {
		it, _ := d.db.NewIter(&pebble.IterOptions{})
		defer it.Close()
		it.SeekLT(keyFormat.Encode())
		it.Next()
		for ; it.Valid(); it.Next() {
			key := it.Key()

			var hash node.TypedHash
			if !keyFormat.Decode(key, &hash) {
				break
			}
			if removeNodes {
				if !logged {
					d.logger.Info("removing some nodes from a multipart restore")
					logged = true
				}

				switch isRoot {
				case false:
					h := hash.Hash()
					// todo
					_ = deleteVersioned(batch, nodeMVCCKeyFmt.Encode(&h), version)
				default:
					// todo
					_ = deleteVersioned(batch, rootNodeMVCCKeyFmt.Encode(&hash), version)
				}
			}
			// Delete the metadata entry as well.
			_ = batch.Delete(key, d.writeOptions)
		}
	}
	cleanNodes(multipartRestoreNodeLogKeyFmt, false)
	cleanNodes(multipartRestoreRootLogKeyFmt, true)

	// Apply the batch first. If anything fails, having corrupt
	// multipart info in d.meta shouldn't hurt us next run.
	if err := d.db.Apply(batch, d.writeOptions); err != nil {
		return err
	}

	if err := d.meta.setMultipartVersion(d.db, multipartVersionNone, d.writeOptions); err != nil {
		return err
	}

	d.multipartVersion = multipartVersionNone
	return nil
}

func (d *pebbleNodeDB) NewBatch(oldRoot node.Root, version uint64, chunk bool) (api.Batch, error) {
	if d.readOnly {
		return nil, api.ErrReadOnly
	}
	if oldRoot.Type != node.RootTypeState && oldRoot.Type != node.RootTypeIO {
		return nil, fmt.Errorf("mkvs/pebbledb: unsupported root type: %s", oldRoot.Type)
	}

	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	if d.multipartVersion != multipartVersionNone && d.multipartVersion != version {
		return nil, api.ErrInvalidMultipartVersion
	}
	if chunk != (d.multipartVersion != multipartVersionNone) {
		return nil, api.ErrMultipartInProgress
	}

	var logBatch *pebble.Batch
	if d.multipartVersion != multipartVersionNone {
		logBatch = d.db.NewBatch()
	}
	return &pebbledbBatch{
		db:             d,
		version:        version,
		rootType:       oldRoot.Type,
		bat:            d.db.NewIndexedBatch(),
		multipartNodes: logBatch,
		oldRoot:        oldRoot,
		chunk:          chunk,
	}, nil
}

func (d *pebbleNodeDB) Size() (uint64, error) {
	return uint64(d.db.Metrics().Total().Size), nil
}

func (d *pebbleNodeDB) Sync() error {
	return d.db.Flush()
}

func (d *pebbleNodeDB) Close() {
	d.closeOnce.Do(func() {
		fmt.Println("Closing")
		d.db.Close()
		d.db = nil
		d.writeOptions = nil
	})
}
