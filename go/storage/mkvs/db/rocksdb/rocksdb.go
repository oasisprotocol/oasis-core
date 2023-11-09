//go:build rocksdb
// +build rocksdb

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
	// TODO: The rootsMetadata is one per version, which means it can also get quite large,
	// maybe use same db options as for nodes CFs? (minus the timestamps).
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

	// multipartRestoreNodeLogKeyFmt is the key format for the root nodes inserted during a chunk restore.
	// Once a set of chunks is fully restored, these entries should be removed. If chunk restoration
	// is interrupted for any reason, the nodes associated with these keys should be removed, along
	// with these entries.
	//
	// Value is empty.
	multipartRestoreRootLogKeyFmt = keyformat.New(0x04, &node.TypedHash{})
)

// Node CF keys (timestamped and used by state and io tree CFs).
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
	defaultFlushOptions = grocksdb.NewDefaultFlushOptions()
)

const (
	cfMetadataName  = "default"
	cfStateTreeName = "state_tree"
	cfIOTreeName    = "io_tree"
)

// New creates a new RocksDB-backed node database.
func New(cfg *api.Config) (api.NodeDB, error) {
	db := &rocksdbNodeDB{
		logger:           logging.GetLogger("mkvs/db/rocksdb"),
		namespace:        cfg.Namespace,
		discardWriteLogs: cfg.DiscardWriteLogs,
		readOnly:         cfg.ReadOnly,
	}

	// XXX: The options bellow were taken from a combination of:
	// - Cosmos-SDK RocksDB implementation
	// - https://github.com/facebook/rocksdb/wiki/RocksDB-Tuning-Guide
	// - https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning
	// Experiment/modify if needed.

	// Create options for the metadata column family.
	// TODO: Consider also tuning some options of the metadata CF (although this is small compared to nodes CFs).
	optsMeta := grocksdb.NewDefaultOptions()
	optsMeta.SetCreateIfMissing(true)
	optsMeta.SetCreateIfMissingColumnFamilies(true)

	// Create options for the node column families.
	// TODO: Consider separate options for state vs. io.
	optsNodes := grocksdb.NewDefaultOptions()
	optsNodes.SetCreateIfMissing(true)
	optsNodes.SetComparator(createTimestampComparator())
	optsNodes.IncreaseParallelism(runtime.NumCPU())

	// General options.
	// https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#other-general-options
	optsNodes.SetLevelCompactionDynamicLevelBytes(true)
	optsNodes.SetBytesPerSync(1048576) // 1 MB.
	optsNodes.OptimizeLevelStyleCompaction(512 * 1024 * 1024)
	optsNodes.SetTargetFileSizeMultiplier(2)

	bbto := grocksdb.NewDefaultBlockBasedTableOptions()
	bbto.SetBlockSize(32 * 1024)
	bbto.SetPinL0FilterAndIndexBlocksInCache(true)
	// Configure block cache. Recommendation is 1/3 of memory budget.
	// https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#block-cache-size
	if cfg.MaxCacheSize == 0 {
		// Default to 128mb block cache size if not configured.
		bbto.SetBlockCache(grocksdb.NewLRUCache(128 * 1024 * 1024))
	} else {
		bbto.SetBlockCache(grocksdb.NewLRUCache(uint64(cfg.MaxCacheSize)))
	}

	// Configure query filter.
	// https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#bloom-filters
	// http://rocksdb.org/blog/2021/12/29/ribbon-filter.html
	bbto.SetFilterPolicy(grocksdb.NewRibbonHybridFilterPolicy(9.9, 1))
	bbto.SetOptimizeFiltersForMemory(true)
	// https://github.com/facebook/rocksdb/wiki/Index-Block-Format#index_type--kbinarysearchwithfirstkey
	bbto.SetIndexType(grocksdb.KBinarySearchWithFirstKey)

	optsNodes.SetBlockBasedTableFactory(bbto)

	// Configure compression.
	// https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#compression
	optsNodes.SetCompression(grocksdb.LZ4Compression)
	optsNodes.SetBottommostCompression(grocksdb.ZSTDCompression)

	// Configure ZSTD (follows Cosmos-SDK values).
	compressOpts := grocksdb.NewDefaultCompressionOptions()
	compressOpts.MaxDictBytes = 110 * 1024 // 110KB - typical size for ZSTD.
	compressOpts.Level = 12                // Higher compression.
	optsNodes.SetBottommostCompressionOptions(compressOpts, true)
	optsNodes.SetBottommostCompressionOptionsZstdMaxTrainBytes(compressOpts.MaxDictBytes*100, true) // 100 * dict size.
	optsNodes.SetCompressionOptionsParallelThreads(4)

	/*
		// TODO: only enable statistics via a config param.
		// 5-10% performance penalty with statistics based on documentation.
		optsMeta.EnableStatistics()
		optsNodes.EnableStatistics()
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
				cfStateTreeName,
				cfIOTreeName,
			},
			[]*grocksdb.Options{
				optsMeta,
				optsNodes,
				optsNodes,
			},
			false)
	case false:
		db.db, cfHandles, err = grocksdb.OpenDbColumnFamilies(
			optsMeta,
			cfg.DB,
			[]string{
				cfMetadataName,
				cfStateTreeName,
				cfIOTreeName,
			},
			[]*grocksdb.Options{
				optsMeta,
				optsNodes,
				optsNodes,
			},
		)
	}
	if err != nil {
		return nil, fmt.Errorf("mkvs/rocksdb: failed to open database: %w", err)
	}
	db.cfMetadata = cfHandles[0] // Also the default handle.
	db.cfStateTree = cfHandles[1]
	db.cfIOTree = cfHandles[2]

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

	db          *grocksdb.DB
	cfMetadata  *grocksdb.ColumnFamilyHandle
	cfStateTree *grocksdb.ColumnFamilyHandle
	cfIOTree    *grocksdb.ColumnFamilyHandle

	closeOnce sync.Once
}

func (d *rocksdbNodeDB) getColumnFamilyForRoot(root node.Root) *grocksdb.ColumnFamilyHandle {
	return d.getColumnFamilyForType(root.Type)
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
	if err != nil {
		return err
	}
	defer item.Free()
	switch {
	case item.Exists():

		// Metadata already exists, just load it and verify that it is
		// compatible with what we have here.
		if err = cbor.UnmarshalTrusted(item.Data(), &d.meta.value); err != nil {
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
	default:
		// No metadata exists, create some.
		d.meta.value.Version = dbVersion
		d.meta.value.Namespace = d.namespace
		if err = d.meta.save(d.db); err != nil {
			return err
		}

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
	cf := d.getColumnFamilyForRoot(root)

	return withTimestampRead(root.Version, func(readOpts *grocksdb.ReadOptions) error {
		s, err := d.db.GetCF(readOpts, cf, rootNodeKeyFmt.Encode(&rootHash))
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
	})
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

	cf := d.getColumnFamilyForRoot(root)
	var n node.Node
	if err := withTimestampRead(root.Version, func(readOpts *grocksdb.ReadOptions) error {
		s, err := d.db.GetCF(readOpts, cf, nodeKeyFmt.Encode(&ptr.Hash))
		if err != nil {
			return fmt.Errorf("mkvs/rocksdb: failed to get node from backing store: %w", err)
		}
		defer s.Free()
		if !s.Exists() {
			return api.ErrNodeNotFound
		}
		n, err = node.UnmarshalBinary(s.Data())
		if err != nil {
			return fmt.Errorf("mkvs/rocksdb: failed to unmarshal node: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
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

	cf := d.getColumnFamilyForRoot(startRoot)

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
			ro := timestampReadOptions(endRoot.Version)
			defer ro.Destroy()
			it := prefixIterator(d.db.NewIteratorCF(ro, cf), prefix)
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

							ro := timestampReadOptions(endRoot.Version)
							defer ro.Destroy()
							item, err := d.db.GetCF(ro, cf, key)
							if err != nil {
								return node.Root{}, nil, err
							}
							defer item.Free()
							if !item.Exists() {
								return node.Root{}, nil, err
							}

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

func (d *rocksdbNodeDB) Finalize(roots []node.Root) error { // nolint: gocyclo
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
	maybeLoneNodes := make(map[hash.Hash]node.RootType)
	notLoneNodes := make(map[hash.Hash]node.RootType)

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
		if err = cbor.UnmarshalTrusted(item.Data(), &updatedNodes); err != nil {
			panic(fmt.Errorf("mkvs/rocksdb: corrupted root updated nodes index: %w", err))
		}
		item.Free()

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
			// Remove any non-finalized roots. It is safe to remove these nodes as RocksDB's version
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
					cf := d.getColumnFamilyForType(rootHash.Type())
					rootWriteLogsPrefix := writeLogKeyFmt.Encode(version, &rootHash)
					ro := timestampReadOptions(version)
					defer ro.Destroy()
					wit := prefixIterator(d.db.NewIteratorCF(ro, cf), rootWriteLogsPrefix)
					defer wit.Close()

					for ; wit.Valid(); wit.Next() {
						batch.DeleteCFWithTS(cf, wit.Key(), ts[:])
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
		if _, ok := notLoneNodes[h]; ok {
			continue
		}

		batch.DeleteCFWithTS(d.getColumnFamilyForType(maybeLoneNodes[h]), nodeKeyFmt.Encode(&h), ts[:])
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
	defer batch.Destroy()
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
			cf := d.getColumnFamilyForRoot(root)

			itRo := timestampReadOptions(root.Version)
			defer itRo.Destroy()
			s, ts, err := d.db.GetCFWithTS(itRo, cf, nodeKeyFmt.Encode(&h))
			if err != nil {
				return false
			}
			defer s.Free()
			if !s.Exists() {
				ts.Free()
				return false
			}

			itemTs, err := versionFromTimestamp(ts)
			if err != nil {
				// Shouldn't happen unless corrupted db.
				panic(fmt.Errorf("mkvs/rocksdb: missing/corrupted timestamp for node: %s", h))
			}
			if itemTs == version {
				batch.DeleteCFWithTS(cf, nodeKeyFmt.Encode(&h), ts.Data())
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

	// Prune roots metadata.
	batch.Delete(rootsMetadataKeyFmt.Encode(version))

	// Prune all write logs in version.
	if !d.discardWriteLogs {
		discardLogs := func(cf *grocksdb.ColumnFamilyHandle) {
			ro := timestampReadOptions(version)
			defer ro.Destroy()
			wit := prefixIterator(d.db.NewIteratorCF(ro, cf), writeLogKeyFmt.Encode(version))
			defer wit.Close()

			for ; wit.Valid(); wit.Next() {
				batch.DeleteCFWithTS(cf, wit.Key(), ts[:])
			}
		}
		discardLogs(d.cfStateTree)
		discardLogs(d.cfIOTree)
	}

	// Update metadata.
	d.meta.setEarliestVersion(batch, version+1)

	if err := d.db.Write(defaultWriteOptions, batch); err != nil {
		return fmt.Errorf("mkvs/rocksdb: failed to prune version %d: %w", version, err)
	}

	if err := d.db.IncreaseFullHistoryTsLow(d.cfIOTree, ts[:]); err != nil {
		return fmt.Errorf("mkvs/rocksdb: failed to prune version %d from IO tree: %w", version, err)
	}
	if err := d.db.IncreaseFullHistoryTsLow(d.cfStateTree, ts[:]); err != nil {
		return fmt.Errorf("mkvs/rocksdb: failed to prune version %d from state tree: %w", version, err)
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

	batch := grocksdb.NewWriteBatch()
	defer batch.Destroy()
	ts := timestampFromVersion(version)
	var logged bool

	// Clean up the node log.
	cleanNodes := func(keyFormat *keyformat.KeyFormat, isRoot bool) {
		it := prefixIterator(d.db.NewIterator(defaultReadOptions), keyFormat.Encode())
		defer it.Close()
		for ; it.Valid(); it.Next() {
			key := it.Key()

			var hash node.TypedHash
			if !keyFormat.Decode(key, &hash) {
				break
			}
			cf := d.getColumnFamilyForType(hash.Type())

			if removeNodes {
				if !logged {
					d.logger.Info("removing some nodes from a multipart restore")
					logged = true
				}

				switch isRoot {
				case false:
					h := hash.Hash()
					batch.DeleteCFWithTS(cf, nodeKeyFmt.Encode(&h), ts[:])
				default:
					cf := d.getColumnFamilyForType(hash.Type())
					batch.DeleteCFWithTS(cf, rootNodeKeyFmt.Encode(&hash), ts[:])
				}
			}
			// Delete the metadata entry as well.
			batch.Delete(key)
		}
	}
	cleanNodes(multipartRestoreNodeLogKeyFmt, false)
	cleanNodes(multipartRestoreRootLogKeyFmt, true)

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
	if d.readOnly {
		return nil, api.ErrReadOnly
	}
	if oldRoot.Type != node.RootTypeState && oldRoot.Type != node.RootTypeIO {
		return nil, fmt.Errorf("mkvs/rocksdb: unsupported root type: %s", oldRoot.Type)
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
		logBatch = grocksdb.NewWriteBatch()
	}

	return &rocksdbBatch{
		db:             d,
		version:        version,
		rootType:       oldRoot.Type,
		bat:            grocksdb.NewWriteBatch(),
		multipartNodes: logBatch,
		oldRoot:        oldRoot,
		chunk:          chunk,
	}, nil
}

func (d *rocksdbNodeDB) Size() (uint64, error) {
	meta := d.db.GetColumnFamilyMetadataCF(d.cfMetadata)
	io := d.db.GetColumnFamilyMetadataCF(d.cfIOTree)
	state := d.db.GetColumnFamilyMetadataCF(d.cfStateTree)

	return meta.Size() + io.Size() + state.Size(), nil
}

func (d *rocksdbNodeDB) Sync() error {
	return d.db.FlushCFs([]*grocksdb.ColumnFamilyHandle{d.cfMetadata, d.cfIOTree, d.cfStateTree}, defaultFlushOptions)
}

func (d *rocksdbNodeDB) Close() {
	d.closeOnce.Do(func() {
		d.db.Close()
		d.cfMetadata = nil
		d.cfIOTree = nil
		d.cfStateTree = nil
		d.db = nil
	})
}

/*
func (d *rocksdbNodeDB) getStats() {
	opts, err := grocksdb.LoadLatestOptions("path", nil, true, nil)
	if err != nil {
		panic(err)
	}
	defer opts.Destroy()
	str := opts.Options().GetStatisticsString()
}
*/
