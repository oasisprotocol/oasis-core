// Package rocksdb provides a RocksDB-backed node database.
package rocksdb

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/linxGnu/grocksdb"

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

// Metadata CF keys (not timestamped).
var (
	// rootsMetadataKeyFmt is the key format for roots metadata. The key format is (version).
	//
	// Value is CBOR-serialized rootsMetadata.
	rootsMetadataKeyFmt = keyformat.New(0x00, uint64(0))

	// rootUpdatedNodesKeyFmt is the key format for the pending updated nodes for the
	// given root that need to be removed only in case the given root is not among
	// the finalized roots. They key format is (version, root).
	//
	// Value is CBOR-serialized []updatedNode.
	rootUpdatedNodesKeyFmt = keyformat.New(0x01, uint64(0), &node.TypedHash{})

	// metadataKeyFmt is the key format for metadata.
	//
	// Value is CBOR-serialized metadata.
	metadataKeyFmt = keyformat.New(0x02)

	// multipartRestoreNodeLogKeyFmt is the key format for the nodes inserted during a chunk restore.
	// Once a set of chunks is fully restored, these entries should be removed. If chunk restoration
	// is interrupted for any reason, the nodes associated with these keys should be removed, along
	// with these entries.
	//
	// Value is empty.
	multipartRestoreNodeLogKeyFmt = keyformat.New(0x03, &node.TypedHash{})
)

// Node CF keys (timestamped).
var (
	// nodeKeyFmt is the key format for nodes (node hash).
	//
	// Value is serialized node.
	nodeKeyFmt = keyformat.New(0x00, &hash.Hash{})

	// writeLogKeyFmt is the key format for write logs (version, new root,
	// old root).
	//
	// Value is CBOR-serialized write log.
	writeLogKeyFmt = keyformat.New(0x01, uint64(0), &node.TypedHash{}, &node.TypedHash{})

	// rootNodeKeyFmt is the key format for root nodes (node hash).
	//
	// Value is empty.
	rootNodeKeyFmt = keyformat.New(0x02, &node.TypedHash{})
)

var (
	defaultWriteOptions = grocksdb.NewDefaultWriteOptions()
	defaultReadOptions  = grocksdb.NewDefaultReadOptions()
)

const (
	cfMetadataName = "default"
	cfNodeTree     = "node"
	// cfStateTreeName = "state_tree"
	// cfIOTreeName    = "io_tree"
)

// New creates a new RocksDB-backed node database.
func New(cfg *api.Config) (api.NodeDB, error) {
	db := &rocksdbNodeDB{
		logger:           logging.GetLogger("mkvs/db/rocksdb"),
		namespace:        cfg.Namespace,
		discardWriteLogs: cfg.DiscardWriteLogs,
		readOnly:         cfg.ReadOnly,
	}

	// XXX: Most of these were taken from Cosmos-SDK RocksDB impl.
	// Experiment/modify if needed. Most of these can be adjusted
	// on a live database.
	// Also see: https://github.com/facebook/rocksdb/wiki/RocksDB-Tuning-Guide

	// Create options for the metadata column family.
	optsMeta := grocksdb.NewDefaultOptions()
	optsMeta.SetCreateIfMissing(true)
	optsMeta.SetCreateIfMissingColumnFamilies(true)

	// Create options for the node column families.
	// TODO: Consider separate options for state vs. io.
	optsNodes := grocksdb.NewDefaultOptions()
	optsNodes.SetCreateIfMissing(true)

	optsNodes.SetComparator(createTimestampComparator())
	optsNodes.IncreaseParallelism(runtime.NumCPU())
	optsNodes.OptimizeLevelStyleCompaction(512 * 1024 * 1024)
	optsNodes.SetTargetFileSizeMultiplier(2)
	optsNodes.SetLevelCompactionDynamicLevelBytes(true)

	bbto := grocksdb.NewDefaultBlockBasedTableOptions()
	bbto.SetBlockSize(32 * 1024)
	if cfg.MaxCacheSize == 0 {
		// Default to 64mb block cache size if not configured.
		bbto.SetBlockCache(grocksdb.NewLRUCache(64 * 1024 * 1024))
	} else {
		bbto.SetBlockCache(grocksdb.NewLRUCache(uint64(cfg.MaxCacheSize)))
	}
	bbto.SetFilterPolicy(grocksdb.NewRibbonHybridFilterPolicy(9.9, 1))
	bbto.SetIndexType(grocksdb.KBinarySearchWithFirstKey)
	optsNodes.SetBlockBasedTableFactory(bbto)
	optsNodes.SetCompressionOptionsParallelThreads(4)

	/*
		// Apparently with dict compression the file writer doesn't report file size:
		// https://github.com/facebook/rocksdb/issues/11146
		// compression options at bottommost level
		opts.SetBottommostCompression(grocksdb.ZSTDCompression)

		compressOpts := grocksdb.NewDefaultCompressionOptions()
		compressOpts.MaxDictBytes = 112640 // 110k
		compressOpts.Level = 12

		opts.SetBottommostCompressionOptions(compressOpts, true)
		opts.SetBottommostCompressionOptionsZstdMaxTrainBytes(compressOpts.MaxDictBytes*100, true)

	*/

	var err error
	var cfHandles []*grocksdb.ColumnFamilyHandle
	switch cfg.ReadOnly {
	case true:
		db.db, cfHandles, err = grocksdb.OpenDbForReadOnlyColumnFamilies(
			optsMeta,
			cfg.DB,
			[]string{
				cfMetadataName,
				cfNodeTree,
				// cfStateTreeName,
				// cfIOTreeName,
			},
			[]*grocksdb.Options{
				optsMeta,
				optsNodes,
				// optsNodes,
			},
			false)
	case false:
		db.db, cfHandles, err = grocksdb.OpenDbColumnFamilies(
			optsMeta,
			cfg.DB,
			[]string{
				cfMetadataName,
				cfNodeTree,
				// cfStateTreeName,
				// cfIOTreeName,
			},
			[]*grocksdb.Options{
				optsMeta,
				optsNodes,
				// optsNodes,
			},
		)
	}
	if err != nil {
		return nil, fmt.Errorf("mkvs/rocksdb: failed to open database: %w", err)
	}
	db.cfMetadata = cfHandles[0] // Also the default handle.
	db.cfNode = cfHandles[1]
	// db.cfStateTree = cfHandles[1]
	// db.cfIOTree = cfHandles[2]

	// Load database metadata.
	if err = db.load(); err != nil {
		db.db.Close()
		return nil, fmt.Errorf("mkvs/rocksdb: failed to load metadata: %w", err)
	}

	// Cleanup any multipart restore remnants, since they can't be used anymore.
	if err = db.cleanMultipartLocked(true); err != nil {
		db.db.Close()
		return nil, fmt.Errorf("mkvs/rocksdb: failed to clean leftovers from multipart restore: %w", err)
	}

	return db, nil
}

type rocksdbNodeDB struct {
	logger   *logging.Logger
	readOnly bool

	namespace common.Namespace

	// metaUpdateLock must be held at any point where data at tsMetadata is read and updated. This
	// is required because all metadata updates happen at the same timestamp and as such conflicts
	// cannot be detected.
	metaUpdateLock   sync.Mutex
	meta             metadata
	multipartVersion uint64

	discardWriteLogs bool

	db         *grocksdb.DB
	cfMetadata *grocksdb.ColumnFamilyHandle
	cfNode     *grocksdb.ColumnFamilyHandle
	// cfStateTree *grocksdb.ColumnFamilyHandle
	// cfIOTree    *grocksdb.ColumnFamilyHandle

	closeOnce sync.Once
}

/*
func (d *rocksdbNodeDB) getColumnFamilyForRoot(root node.Root) *grocksdb.ColumnFamilyHandle {
	switch root.Type {
	case node.RootTypeState:
		return d.cfStateTree
	case node.RootTypeIO:
		return d.cfIOTree
	default:
		panic(fmt.Errorf("unsupported root type: %s", root.Type))
	}
}


func (d *rocksdbNodeDB) getColumnFamilyForType(rootType node.RootType) *grocksdb.ColumnFamilyHandle {
	switch rootType {
	case node.RootTypeState:
		return d.cfStateTree
	case node.RootTypeIO:
		return d.cfIOTree
	default:
		panic(fmt.Errorf("unsupported root type: %s", rootType))
	}
}
*/

func (d *rocksdbNodeDB) load() error {
	/*
		// Check first if the database is even usable.
		_, err := d.db.Get(migrationMetaKeyFm.Encode())
		if err == nil {
			return api.ErrUpgradeInProgress
		}
	*/

	// Load metadata.
	item, err := d.db.Get(defaultReadOptions, metadataKeyFmt.Encode())
	switch err {
	case nil:
		if !item.Exists() {
			break
		}
		defer item.Free()

		// Metadata already exists, just load it and verify that it is
		// compatible with what we have here.
		if err := cbor.UnmarshalTrusted(item.Data(), &d.meta.value); err != nil {
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
	default:
		return err
	}

	// No metadata exists, create some.
	d.meta.value.Version = dbVersion
	d.meta.value.Namespace = d.namespace
	if err = d.meta.save(d.db); err != nil {
		return err
	}

	return nil
}

func (d *rocksdbNodeDB) sanityCheckNamespace(ns common.Namespace) error {
	if !ns.Equal(&d.namespace) {
		return api.ErrBadNamespace
	}
	return nil
}

func (d *rocksdbNodeDB) checkRoot(root node.Root) error {
	rootHash := node.TypedHashFromRoot(root)

	s, err := d.db.GetCF(timestampReadOptions(root.Version), d.cfNode, rootNodeKeyFmt.Encode(&rootHash))
	if err != nil {
		d.logger.Error("failed to check root existence",
			"err", err,
		)
		return fmt.Errorf("mkvs/rocksdb: failed to get root from backing store: %w", err)
	}
	defer s.Free()
	if !s.Exists() {
		return api.ErrRootNotFound
	}
	return nil
}

// Implements api.NodeDB.
func (d *rocksdbNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("mkvs/rocksdb: attempted to get invalid pointer from node database")
	}
	if err := d.sanityCheckNamespace(root.Namespace); err != nil {
		return nil, err
	}

	// If the version is earlier than the earliest version, we don't have the node (it was pruned).
	// Note that the key can still be present in the database until it gets compacted.
	if root.Version < d.meta.getEarliestVersion() {
		return nil, api.ErrNodeNotFound
	}

	// Check if the root actually exists.
	if err := d.checkRoot(root); err != nil {
		return nil, err
	}

	// cf := d.getColumnFamilyForRoot(root)
	s, err := d.db.GetCF(timestampReadOptions(root.Version), d.cfNode, nodeKeyFmt.Encode(&ptr.Hash))
	if err != nil {
		return nil, fmt.Errorf("mkvs/rocksdb: failed to get node from backing store: %w", err)
	}
	defer s.Free()
	if !s.Exists() {
		return nil, api.ErrNodeNotFound
	}

	var n node.Node
	n, err = node.UnmarshalBinary(s.Data())
	if err != nil {
		return nil, fmt.Errorf("mkvs/rocksdb: failed to unmarshal node: %w", err)
	}

	return n, nil
}

func (d *rocksdbNodeDB) GetWriteLog(ctx context.Context, startRoot, endRoot node.Root) (writelog.Iterator, error) {
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
	// cf := d.getColumnFamilyForType(startRootHash.Type())
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		curItem := queue[0]
		queue = queue[1:]

		wl, err := func() (writelog.Iterator, error) {
			// Iterate over all write logs that result in the current item.
			prefix := writeLogKeyFmt.Encode(endRoot.Version, &curItem.endRootHash)
			it := prefixIterator(d.db.NewIteratorCF(timestampReadOptions(endRoot.Version), d.cfNode), prefix)
			defer it.Close()

			for ; it.Valid(); it.Next() {

				if ctx.Err() != nil {
					return nil, ctx.Err()
				}

				key := it.Key()

				var decVersion uint64
				var decEndRootHash node.TypedHash
				var decStartRootHash node.TypedHash

				if !writeLogKeyFmt.Decode(key, &decVersion, &decEndRootHash, &decStartRootHash) {
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

							item, err := d.db.GetCF(timestampReadOptions(endRoot.Version), d.cfNode, key)
							if err != nil || !item.Exists() {
								return node.Root{}, nil, err
							}
							defer item.Free()

							var log api.HashedDBWriteLog
							if err := cbor.UnmarshalTrusted(item.Data(), &log); err != nil {
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

func (d *rocksdbNodeDB) GetLatestVersion() (uint64, bool) {
	return d.meta.getLastFinalizedVersion()
}

func (d *rocksdbNodeDB) GetEarliestVersion() uint64 {
	return d.meta.getEarliestVersion()
}

func (d *rocksdbNodeDB) GetRootsForVersion(version uint64) ([]node.Root, error) {
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

func (d *rocksdbNodeDB) HasRoot(root node.Root) bool {
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

func (d *rocksdbNodeDB) Finalize(roots []node.Root) error {
	if len(roots) == 0 {
		return fmt.Errorf("mkvs/rocksdb: need at least one root to finalize")
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

	batch := grocksdb.NewWriteBatch()
	defer batch.Destroy()
	ts := timestampFromVersion(version)

	// Go through all roots and prune them based on whether they are finalized or not.
	maybeLoneNodes := make(map[hash.Hash]bool)
	notLoneNodes := make(map[hash.Hash]bool)

	for rootHash := range rootsMeta.Roots {
		// TODO: Consider colocating updated nodes with the root metadata.
		rootUpdatedNodesKey := rootUpdatedNodesKeyFmt.Encode(version, &rootHash)

		// Load hashes of nodes added during this version for this root.
		item, err := d.db.Get(defaultReadOptions, rootUpdatedNodesKey)
		if err != nil {
			panic(fmt.Errorf("mkvs/rocksdb: corrupted root updated nodes index: %w", err))
		}
		if !item.Exists() {
			panic(fmt.Errorf("mkvs/rocksdb: missing root updated nodes index"))
		}

		var updatedNodes []updatedNode
		if err := cbor.UnmarshalTrusted(item.Data(), &updatedNodes); err != nil {
			panic(fmt.Errorf("mkvs/rocksdb: corrupted root updated nodes index: %w", err))
		}
		item.Free()

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
			// Remove any non-finalized roots. It is safe to remove these nodes as RocksDB's version
			// control will make sure they are not removed if they are resurrected in any later
			// version as long as we make sure that these nodes are not shared with any finalized
			// roots added in the same version.
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
					wit := prefixIterator(d.db.NewIteratorCF(timestampReadOptions(version), d.cfNode), rootWriteLogsPrefix)
					defer wit.Close()

					// cf := d.getColumnFamilyForType(rootHash.Type())
					for ; wit.Valid(); wit.Next() {
						batch.DeleteCFWithTS(d.cfNode, wit.Key(), ts[:])
					}
					return nil
				}(); err != nil {
					return err
				}
			}
		}

		// Set of updated nodes no longer needed after finalization.
		batch.Delete(rootUpdatedNodesKey)
	}

	// Clean any lone nodes.
	for h := range maybeLoneNodes {
		if notLoneNodes[h] {
			continue
		}

		// TODO: get CF for hash?
		// batch.DeleteCFWithTS(d.cfIOTree, nodeKeyFmt.Encode(&h), ts[:])
		// batch.DeleteCFWithTS(d.cfStateTree, nodeKeyFmt.Encode(&h), ts[:])
		batch.DeleteCFWithTS(d.cfNode, nodeKeyFmt.Encode(&h), ts[:])
	}

	// Save roots metadata if changed.
	if rootsChanged {
		rootsMeta.save(batch)
	}

	// Update last finalized version.
	d.meta.setLastFinalizedVersion(batch, version)

	// Commit batch.
	if err := d.db.Write(defaultWriteOptions, batch); err != nil {
		return fmt.Errorf("mkvs/rocksdb: failed to commit finalized roots: %w", err)
	}

	// Clean multipart metadata if there is any.
	if d.multipartVersion != multipartVersionNone {
		if err := d.cleanMultipartLocked(false); err != nil {
			return err
		}
	}
	return nil
}

func (d *rocksdbNodeDB) Prune(ctx context.Context, version uint64) error {
	ts := timestampFromVersion(version)

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

	rootsMeta, err := loadRootsMetadata(d.db, version)
	if err != nil {
		return err
	}

	batch := grocksdb.NewWriteBatch()
	for rootHash, derivedRoots := range rootsMeta.Roots {
		if len(derivedRoots) > 0 {
			// Not a lone root.
			continue
		}

		// Traverse the root and prune all items created in this version.
		root := node.Root{
			Namespace: d.namespace,
			Version:   version,
			Type:      rootHash.Type(),
			Hash:      rootHash.Hash(),
		}
		var innerErr error
		err := api.Visit(ctx, d, root, func(ctx context.Context, n node.Node) bool {
			h := n.GetHash()

			s, ts, err := d.db.GetCFWithTS(timestampReadOptions(root.Version), d.cfNode, nodeKeyFmt.Encode(&h))
			if err != nil {
				return false
			}
			defer s.Free()
			if !s.Exists() {
				return false
			}

			itemTs, err := versionFromTimestamp(ts)
			if err != nil {
				// Shouldn't happen unless corrupted db.
				panic(fmt.Errorf("mkvs/rocksdb: missing/corrupted timestamp for node: %s", h))
			}
			if itemTs == version {
				batch.DeleteCFWithTS(d.cfNode, nodeKeyFmt.Encode(&h), ts.Data())
			}
			return true
		})
		if innerErr != nil {
			return innerErr
		}
		if err != nil {
			return err
		}

		batch.Delete(rootNodeKeyFmt.Encode(&rootHash))
	}

	// Prune all write logs in version.
	if !d.discardWriteLogs {
		wit := prefixIterator(d.db.NewIteratorCF(timestampReadOptions(version), d.cfNode), writeLogKeyFmt.Encode(version))
		defer wit.Close()

		for ; wit.Valid(); wit.Next() {
			batch.DeleteCFWithTS(d.cfNode, wit.Key(), ts[:])
		}

	}

	// Update metadata.
	d.meta.setEarliestVersion(batch, version+1)

	if err := d.db.Write(defaultWriteOptions, batch); err != nil {
		return fmt.Errorf("mkvs/rocksdb: failed to prune version %d: %w", version, err)
	}

	// if err := d.db.IncreaseFullHistoryTsLow(d.cfIOTree, ts[:]); err != nil {
	// 	return fmt.Errorf("mkvs/rocksdb: failed to prune version %d from IO tree: %w", version, err)
	// }
	// if err := d.db.IncreaseFullHistoryTsLow(d.cfStateTree, ts[:]); err != nil {
	// 	return fmt.Errorf("mkvs/rocksdb: failed to prune version %d from state tree: %w", version, err)
	// }
	if err := d.db.IncreaseFullHistoryTsLow(d.cfNode, ts[:]); err != nil {
		return fmt.Errorf("mkvs/rocksdb: failed to prune version %d from nodes tree: %w", version, err)
	}
	return nil
}

func (d *rocksdbNodeDB) StartMultipartInsert(version uint64) error {
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

	if err := d.meta.setMultipartVersion(d.db, version); err != nil {
		return err
	}
	d.multipartVersion = version

	return nil
}

func (d *rocksdbNodeDB) AbortMultipartInsert() error {
	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	return d.cleanMultipartLocked(true)
}

// Assumes metaUpdateLock is held when called.
func (d *rocksdbNodeDB) cleanMultipartLocked(removeNodes bool) error {
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

	it := prefixIterator(d.db.NewIterator(defaultReadOptions), multipartRestoreNodeLogKeyFmt.Encode())
	defer it.Close()

	batch := grocksdb.NewWriteBatch()
	defer batch.Destroy()
	ts := timestampFromVersion(version)
	var logged bool
	for ; it.Valid(); it.Next() {
		key := it.Key()

		var hash node.TypedHash
		if !multipartRestoreNodeLogKeyFmt.Decode(key, &hash) {
			break
		}

		if removeNodes {
			if !logged {
				d.logger.Info("removing some nodes from a multipart restore")
				logged = true
			}
			switch hash.Type() {
			case node.RootTypeInvalid:
				h := hash.Hash()
				batch.DeleteCFWithTS(d.cfNode, nodeKeyFmt.Encode(&h), ts[:])
			default:
				// cf := d.getColumnFamilyForType(hash.Type())
				batch.DeleteCFWithTS(d.cfNode, rootNodeKeyFmt.Encode(&hash), ts[:])
			}
		}
		// Delete the metadata entry as well.
		batch.Delete(key)
	}

	// Apply the batch first. If anything fails, having corrupt
	// multipart info in d.meta shouldn't hurt us next run.
	if err := d.db.Write(defaultWriteOptions, batch); err != nil {
		return err
	}

	if err := d.meta.setMultipartVersion(d.db, multipartVersionNone); err != nil {
		return err
	}

	d.multipartVersion = multipartVersionNone
	return nil
}

func (d *rocksdbNodeDB) NewBatch(oldRoot node.Root, version uint64, chunk bool) (api.Batch, error) {
	// WARNING: There is a maximum batch size and maximum batch entry count.
	// Both of these things are derived from the MaxTableSize option.
	//
	// The size limit also applies to normal transactions, so the "right"
	// thing to do would be to either crank up MaxTableSize or maybe split
	// the transaction out.

	if d.readOnly {
		return nil, api.ErrReadOnly
	}

	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	if d.multipartVersion != multipartVersionNone && d.multipartVersion != version {
		return nil, api.ErrInvalidMultipartVersion
	}
	if chunk != (d.multipartVersion != multipartVersionNone) {
		return nil, api.ErrMultipartInProgress
	}

	var logBatch *grocksdb.WriteBatch
	if d.multipartVersion != multipartVersionNone {
		// The node log is at a different version than the nodes themselves,
		// which is awkward.
		logBatch = grocksdb.NewWriteBatch()
	}

	return &rocksdbBatch{
		db:             d,
		version:        version,
		bat:            grocksdb.NewWriteBatch(),
		multipartNodes: logBatch,
		oldRoot:        oldRoot,
		chunk:          chunk,
	}, nil
}

func (d *rocksdbNodeDB) Size() (uint64, error) {
	meta := d.db.GetColumnFamilyMetadataCF(d.cfMetadata)
	// io := d.db.GetColumnFamilyMetadataCF(d.cfIOTree)
	// state := d.db.GetColumnFamilyMetadataCF(d.cfStateTree)
	node := d.db.GetColumnFamilyMetadataCF(d.cfNode)

	return meta.Size() + node.Size(), nil // io.Size() + state.Size(), nil
}

func (d *rocksdbNodeDB) Sync() error {
	opts := grocksdb.NewDefaultFlushOptions()
	return d.db.FlushCFs([]*grocksdb.ColumnFamilyHandle{d.cfMetadata, d.cfNode}, opts)
}

func (d *rocksdbNodeDB) Close() {
	d.closeOnce.Do(func() {
		d.db.Close()
		d.cfMetadata = nil
		// d.cfIOTree = nil
		// d.cfStateTree = nil
		d.cfNode = nil
		d.db = nil
	})
}
