// Package badger provides a RocksDB-backed node database.
package rocksdb

import (
	"context"
	"fmt"
	"runtime"

	"github.com/linxGnu/grocksdb"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const (
	cfMetadataName = "default"
	cfStateTreeName    = "state_tree"
	cfIOTreeName = "io_tree"
)

// New creates a new BadgerDB-backed node database.
func New(cfg *api.Config) (api.NodeDB, error) {
	db := &rocksdbNodeDB{
		logger:           logging.GetLogger("mkvs/db/rocksdb"),
		namespace:        cfg.Namespace,
		readOnly:         cfg.ReadOnly,
		discardWriteLogs: cfg.DiscardWriteLogs,
	}

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
		if !sstFileWriter {
			// compression options at bottommost level
			opts.SetBottommostCompression(grocksdb.ZSTDCompression)
			compressOpts := grocksdb.NewDefaultCompressionOptions()
			compressOpts.MaxDictBytes = 112640 // 110k
			compressOpts.Level = 12
			opts.SetBottommostCompressionOptions(compressOpts, true)
			opts.SetBottommostCompressionOptionsZstdMaxTrainBytes(compressOpts.MaxDictBytes*100, true)
		}*/

	dbHandle, cfHandles, err := grocksdb.OpenDbColumnFamilies(
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
	if err != nil {
		return nil, err
	}

	db.db = dbHandle
	// Metadata column family is the default so no explicit handle is needed.
	db.cfStateTree = cfHandles[1]
	db.cfIOTree = cfHandles[2]

	return db, nil
}

type rocksdbNodeDB struct {
	logger *logging.Logger

	namespace common.Namespace

	readOnly         bool
	discardWriteLogs bool

	db      *grocksdb.DB
	cfStateTree *grocksdb.ColumnFamilyHandle
	cfIOTree *grocksdb.ColumnFamilyHandle
}

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

func (d *rocksdbNodeDB) sanityCheckNamespace(ns common.Namespace) error {
	if !ns.Equal(&d.namespace) {
		return api.ErrBadNamespace
	}
	return nil
}

/*

one root per column family

key -> node

*/

func (d *rocksdbNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("mkvs/rocksdb: attempted to get invalid pointer from node database")
	}
	if err := d.sanityCheckNamespace(root.Namespace); err != nil {
		return nil, err
	}

	cf := d.getColumnFamilyForRoot(root)

	return nil, fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) GetWriteLog(ctx context.Context, startRoot, endRoot node.Root) (writelog.Iterator, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) GetLatestVersion() (uint64, bool) {
	return 0, false
}

func (d *rocksdbNodeDB) GetEarliestVersion() uint64 {
	return 0
}

func (d *rocksdbNodeDB) GetRootsForVersion(ctx context.Context, version uint64) (roots []node.Root, err error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) HasRoot(root node.Root) bool {
	return false
}

func (d *rocksdbNodeDB) Finalize(ctx context.Context, roots []node.Root) error {
	return fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) Prune(ctx context.Context, version uint64) error {
	return nil
}

func (d *rocksdbNodeDB) StartMultipartInsert(version uint64) error {
	return fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) AbortMultipartInsert() error {
	return fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) NewBatch(oldRoot node.Root, version uint64, chunk bool) (api.Batch, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) Size() (int64, error) {
	return 0, fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) Sync() error {
	return fmt.Errorf("not yet implemented")
}

func (d *rocksdbNodeDB) Close() {
	d.db.Close()
}
