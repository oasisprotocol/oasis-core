package api

import (
	"context"
	"sync"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cache/lru"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

// RootCache is a LRU based tree cache.
type RootCache struct {
	localDB      nodedb.NodeDB
	remoteSyncer syncer.ReadSyncer

	insecureSkipChecks bool

	rootCache       *lru.Cache
	applyLocks      *lru.Cache
	applyLocksGuard sync.Mutex

	persistEverything urkel.Option
}

// GetTree gets a tree entry from the cache by the root iff present, or creates
// a new tree with the specified root in the node database.
func (rc *RootCache) GetTree(ctx context.Context, root Root) (*urkel.Tree, error) {
	cachedTree, present := rc.rootCache.Get(root.EncodedHash())
	if present {
		return cachedTree.(*urkel.Tree), nil
	}

	newTree, err := urkel.NewWithRoot(ctx, rc.remoteSyncer, rc.localDB, root, rc.persistEverything)
	if err != nil {
		return nil, errors.Wrap(err, "storage/rootcache: failed to create new tree")
	}

	return newTree, nil
}

// Apply applies the write log, bypassing the apply operation iff the new root
// already is in the node database.
func (rc *RootCache) Apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog WriteLog,
) (*hash.Hash, error) {
	root := Root{
		Namespace: ns,
		Round:     srcRound,
		Hash:      srcRoot,
	}
	expectedNewRoot := Root{
		Namespace: ns,
		Round:     dstRound,
		Hash:      dstRoot,
	}

	// Sanity check the expected new root.
	if !expectedNewRoot.Follows(&root) {
		return nil, errors.New("storage/rootcache: expected root does not follow root")
	}

	mu := rc.getApplyLock(root, expectedNewRoot)
	mu.Lock()
	defer mu.Unlock()

	var r hash.Hash

	// Check if we already have the expected new root in our local DB.
	if rc.localDB.HasRoot(expectedNewRoot) {
		// We do, don't apply anything.
		r = dstRoot

		// Do a fake get to update the LRU cache frequency.
		_, _ = rc.rootCache.Get(expectedNewRoot.EncodedHash())
	} else {
		// We don't, apply operations.
		tree, err := urkel.NewWithRoot(ctx, rc.remoteSyncer, rc.localDB, root, rc.persistEverything)
		if err != nil {
			return nil, err
		}

		for _, entry := range writeLog {
			if len(entry.Value) == 0 {
				err = tree.Remove(ctx, entry.Key)
			} else {
				err = tree.Insert(ctx, entry.Key, entry.Value)
			}
			if err != nil {
				return nil, err
			}
		}

		if !rc.insecureSkipChecks {
			_, err = tree.CommitKnown(ctx, expectedNewRoot)
		} else {
			// Skip known root checks -- only for use in benchmarks.
			_, r, err = tree.Commit(ctx, ns, dstRound)
			dstRoot = r
			expectedNewRoot.Hash = r
		}
		switch err {
		case nil:
			r = dstRoot
		case urkel.ErrKnownRootMismatch:
			return nil, ErrExpectedRootMismatch
		default:
			return nil, err
		}

		// Also save tree root in local LRU cache.
		_ = rc.rootCache.Put(expectedNewRoot.EncodedHash(), tree)
	}

	return &r, nil
}

func (rc *RootCache) getApplyLock(root, expectedNewRoot Root) *sync.Mutex {
	// Lock the Apply call based on (oldRoot, expectedNewRoot), so that when
	// multiple compute committees commit the same write logs, we only write
	// the first one and go through the fast path for the rest.
	lockID := root.EncodedHash().String() + expectedNewRoot.EncodedHash().String()

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

func NewRootCache(
	localDB nodedb.NodeDB,
	remoteSyncer syncer.ReadSyncer,
	lruSizeInBytes uint64,
	applyLockLRUSlots uint64,
	insecureSkipChecks bool,
) (*RootCache, error) {
	rootCache, err := lru.New(lru.Capacity(lruSizeInBytes, true))
	if err != nil {
		return nil, errors.Wrap(err, "storage/rootcache: failed to create rootCache")
	}

	applyLocks, err := lru.New(lru.Capacity(applyLockLRUSlots, false))
	if err != nil {
		return nil, errors.Wrap(err, "storage/rootcache: failed to create applyLocks")
	}

	// In the cachingclient, we want to persist everything that we obtain
	// from the remote syncer in our local database.
	persistEverything := urkel.PersistEverythingFromSyncer(remoteSyncer != nil)

	return &RootCache{
		localDB:            localDB,
		remoteSyncer:       remoteSyncer,
		insecureSkipChecks: insecureSkipChecks,
		rootCache:          rootCache,
		applyLocks:         applyLocks,
		persistEverything:  persistEverything,
	}, nil
}
