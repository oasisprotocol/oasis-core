package api

import (
	"context"
	"sync"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cache/lru"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
)

// RootCache is a LRU based tree cache.
type RootCache struct {
	nodedb nodedb.NodeDB

	rootCache       *lru.Cache
	applyLocks      *lru.Cache
	applyLocksGuard sync.Mutex
}

// GetTree gets a tree entry from the cache by the root iff present, or creates
// a new tree with the specified root in the node database.
func (rc *RootCache) GetTree(ctx context.Context, root hash.Hash) (*urkel.Tree, error) {
	cachedTree, present := rc.rootCache.Get(root)
	if present {
		return cachedTree.(*urkel.Tree), nil
	}

	newTree, err := urkel.NewWithRoot(ctx, nil, rc.nodedb, root)
	if err != nil {
		return nil, errors.Wrap(err, "storage/rootcache: failed to create new tree")
	}

	return newTree, nil
}

// Apply applies the write log, bypassing the apply operation iff the new root
// already is in the node database.
func (rc *RootCache) Apply(ctx context.Context, root, expectedNewRoot hash.Hash, log WriteLog) (*hash.Hash, error) {
	mu := rc.getApplyLock(root, expectedNewRoot)
	mu.Lock()
	defer mu.Unlock()

	var r hash.Hash

	// Check if we already have the expected new root in our local DB.
	if urkel.HasRoot(rc.nodedb, expectedNewRoot) {
		// We do, don't apply anything.
		r = expectedNewRoot

		// Do a fake get to update the LRU cache frequency.
		_, _ = rc.rootCache.Get(expectedNewRoot)
	} else {
		// We don't, apply operations.
		tree, err := urkel.NewWithRoot(ctx, nil, rc.nodedb, root)
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
		_ = rc.rootCache.Put(r, tree)
	}

	return &r, nil
}

func (rc *RootCache) getApplyLock(root, expectedNewRoot hash.Hash) *sync.Mutex {
	// Lock the Apply call based on (oldRoot, expectedNewRoot), so that when
	// multiple compute committees commit the same write logs, we only write
	// the first one and go through the fast path for the rest.
	lockID := root.String() + expectedNewRoot.String()

	rc.applyLocksGuard.Lock()
	defer rc.applyLocksGuard.Unlock()

	cachedLock, present := rc.applyLocks.Get(lockID)
	if present {
		return cachedLock.(*sync.Mutex)
	}

	var lock sync.Mutex
	_ = rc.applyLocks.Put(lockID, &lock)
	return &lock
}

func NewRootCache(nodedb nodedb.NodeDB, lruSizeInBytes, applyLockLRUSlots uint64) (*RootCache, error) {
	rootCache, err := lru.New(lru.Capacity(lruSizeInBytes, true))
	if err != nil {
		return nil, errors.Wrap(err, "storage/rootcache: failed to create rootCache")
	}

	applyLocks, err := lru.New(lru.Capacity(applyLockLRUSlots, false))
	if err != nil {
		return nil, errors.Wrap(err, "storage/rootcache: failed to create applyLocks")
	}

	return &RootCache{
		nodedb:     nodedb,
		rootCache:  rootCache,
		applyLocks: applyLocks,
	}, nil
}
