// Package leveldb implements the LevelDB backed storage backend.
package leveldb

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"

	"github.com/oasislabs/ekiden/go/common/cache/lru"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "leveldb"

	// DBFile is the default backing store filename.
	DBFile = "storage.leveldb.db"

	// MKVSDBFile is the default MKVS backing store filename.
	MKVSDBFile = "mkvs_storage.leveldb.db"
)

var (
	_ api.Backend = (*leveldbBackend)(nil)

	keyVersion = []byte("version")
	dbVersion  = []byte{0x00}

	leveldbSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ekiden_storage_leveldb_size",
			Help: "Total size of the leveldb table(s) (MiB)",
		},
	)
	leveldbCollectors = []prometheus.Collector{
		leveldbSize,
	}

	metricsOnce sync.Once
)

type leveldbBackend struct {
	logger     *logging.Logger
	db         *leveldb.DB
	nodedb     nodedb.NodeDB
	rootCache  *lru.Cache
	applyLocks *lru.Cache

	signingKey *signature.PrivateKey

	closeOnce sync.Once
}

func (b *leveldbBackend) apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*hash.Hash, error) {
	// Lock the Apply call based on (oldRoot, expectedNewRoot), so that when
	// multiple compute committees commit the same write logs, we only write
	// the first one and go through the fast path for the rest.
	// TBD: Should we also take into account the write log itself?
	lockID := root.String() + expectedNewRoot.String()
	cachedLock, present := b.applyLocks.Get(lockID)
	var lock *sync.Mutex
	if !present {
		// Make new lock if it doesn't exist in the LRU cache already.
		lock = &sync.Mutex{}
		_ = b.applyLocks.Put(lockID, lock)
	} else {
		lock = cachedLock.(*sync.Mutex)
	}
	lock.Lock()
	defer lock.Unlock()

	var r hash.Hash

	// Check if we already have the expected new root in our local DB.
	if urkel.HasRoot(b.nodedb, expectedNewRoot) {
		// We do, don't apply anything.
		r = expectedNewRoot

		// Do a fake get to update the LRU cache frequency.
		_, _ = b.rootCache.Get(expectedNewRoot)
	} else {
		// We don't, apply operations.
		tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}

		for _, entry := range log {
			if len(entry.Value) == 0 {
				err = tree.Remove(ctx, entry.Key)
			} else {
				err = tree.Insert(ctx, entry.Key, entry.Value)
			}
			if err != nil {
				return nil, err
			}
		}

		_, r, err = tree.Commit(ctx)
		if err != nil {
			return nil, err
		}

		// Also save tree root in local LRU cache.
		_ = b.rootCache.Put(root, tree)
	}

	return &r, nil
}

func (b *leveldbBackend) signReceipt(ctx context.Context, roots []hash.Hash) (*api.MKVSReceipt, error) {
	receipt := api.MKVSReceiptBody{
		Version: 1,
		Roots:   roots,
	}
	signed, err := signature.SignSigned(*b.signingKey, api.MKVSReceiptSignatureContext, &receipt)
	if err != nil {
		return nil, err
	}

	return &api.MKVSReceipt{
		Signed: *signed,
	}, nil
}

func (b *leveldbBackend) ApplyBatch(ctx context.Context, ops []api.ApplyOp) (*api.MKVSReceipt, error) {
	var roots []hash.Hash
	for _, op := range ops {
		root, err := b.apply(ctx, op.Root, op.ExpectedNewRoot, op.WriteLog)
		if err != nil {
			return nil, err
		}
		roots = append(roots, *root)
	}

	return b.signReceipt(ctx, roots)
}

func (b *leveldbBackend) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*api.MKVSReceipt, error) {
	r, err := b.apply(ctx, root, expectedNewRoot, log)
	if err != nil {
		return nil, err
	}

	return b.signReceipt(ctx, []hash.Hash{*r})
}

func (b *leveldbBackend) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	// First, check local tree root cache.
	var tree *urkel.Tree
	cachedTree, present := b.rootCache.Get(root)
	if present {
		// Use cached tree.
		tree = cachedTree.(*urkel.Tree)
	} else {
		// Tree not found in cache, make new one.
		newTree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}
		tree = newTree
	}

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *leveldbBackend) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	// First, check local tree root cache.
	var tree *urkel.Tree
	cachedTree, present := b.rootCache.Get(root)
	if present {
		// Use cached tree.
		tree = cachedTree.(*urkel.Tree)
	} else {
		// Tree not found in cache, make new one.
		newTree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}
		tree = newTree
	}

	return tree.GetPath(ctx, root, key, startDepth)
}

func (b *leveldbBackend) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	// First, check local tree root cache.
	var tree *urkel.Tree
	cachedTree, present := b.rootCache.Get(root)
	if present {
		// Use cached tree.
		tree = cachedTree.(*urkel.Tree)
	} else {
		// Tree not found in cache, make new one.
		newTree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}
		tree = newTree
	}

	return tree.GetNode(ctx, root, id)
}

func (b *leveldbBackend) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	// First, check local tree root cache.
	var tree *urkel.Tree
	cachedTree, present := b.rootCache.Get(root)
	if present {
		// Use cached tree.
		tree = cachedTree.(*urkel.Tree)
	} else {
		// Tree not found in cache, make new one.
		newTree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}
		tree = newTree
	}

	return tree.GetValue(ctx, root, id)
}

func (b *leveldbBackend) Cleanup() {
	b.closeOnce.Do(func() {
		b.nodedb.Close()
		_ = b.db.Close()
	})
}

func (b *leveldbBackend) Initialized() <-chan struct{} {
	initCh := make(chan struct{})
	close(initCh)
	return initCh
}

func (b *leveldbBackend) updateMetrics() {
	var stats leveldb.DBStats
	if err := b.db.Stats(&stats); err != nil {
		b.logger.Error("Stats",
			"err", err,
		)
		return
	}

	var total int64
	for _, v := range stats.LevelSizes {
		total += v
	}
	leveldbSize.Set(float64(total) / 1024768.0)
}

func checkVersion(db *leveldb.DB) error {
	ver, err := db.Get(keyVersion, nil)
	switch err {
	case leveldb.ErrNotFound:
		return db.Put(keyVersion, dbVersion, nil)
	case nil:
		break
	default:
		return err
	}

	if !bytes.Equal(ver, dbVersion) {
		return fmt.Errorf("storage/leveldb: incompatible LevelDB store version: '%v'", hex.EncodeToString(ver))
	}

	return nil
}

// New constructs a new LevelDB backed storage Backend instance, using
// the provided path for the database.
func New(dbDir string, mkvsDBDir string, signingKey *signature.PrivateKey, lruSizeInBytes uint64, applyLockLRUSlots uint64) (api.Backend, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(leveldbCollectors...)
	})

	db, err := leveldb.OpenFile(dbDir, nil)
	if err != nil {
		return nil, err
	}

	if err = checkVersion(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	ndb, err := nodedb.NewLevelDBNodeDB(mkvsDBDir)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	rootCache, err := lru.New(lru.Capacity(lruSizeInBytes, true))
	if err != nil {
		ndb.Close()
		_ = db.Close()
		return nil, err
	}

	applyLocks, err := lru.New(lru.Capacity(applyLockLRUSlots, false))
	if err != nil {
		ndb.Close()
		_ = db.Close()
		return nil, err
	}

	b := &leveldbBackend{
		logger:     logging.GetLogger("storage/leveldb"),
		db:         db,
		nodedb:     ndb,
		rootCache:  rootCache,
		applyLocks: applyLocks,
		signingKey: signingKey,
	}
	b.updateMetrics()

	return b, nil
}
