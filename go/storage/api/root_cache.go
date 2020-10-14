package api

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/cache/lru"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	nodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

// RootCache is a LRU based tree cache.
type RootCache struct {
	localDB      nodedb.NodeDB
	remoteSyncer syncer.ReadSyncer

	insecureSkipChecks bool

	applyLocks      *lru.Cache
	applyLocksGuard sync.Mutex

	persistEverything mkvs.Option
}

// GetTree gets a tree entry from the cache by the root iff present, or creates
// a new tree with the specified root in the node database.
func (rc *RootCache) GetTree(ctx context.Context, root Root) (mkvs.Tree, error) {
	return mkvs.NewWithRoot(rc.remoteSyncer, rc.localDB, root, rc.persistEverything), nil
}

// Apply applies the write log, bypassing the apply operation iff the new root
// already is in the node database.
func (rc *RootCache) Apply(
	ctx context.Context,
	root Root,
	expectedNewRoot Root,
	writeLog WriteLog,
) (*hash.Hash, error) {
	// Sanity check the expected new root.
	if !expectedNewRoot.Follows(&root) {
		return nil, ErrRootMustFollowOld
	}

	mu := rc.getApplyLock(root, expectedNewRoot)
	mu.Lock()
	defer mu.Unlock()

	r := expectedNewRoot.Hash

	// Check if we already have the expected new root in our local DB.
	if !rc.localDB.HasRoot(expectedNewRoot) {
		// We don't, apply operations.
		tree := mkvs.NewWithRoot(rc.remoteSyncer, rc.localDB, root, rc.persistEverything)
		defer tree.Close()

		if err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog)); err != nil {
			return nil, err
		}

		var err error
		if !rc.insecureSkipChecks {
			_, err = tree.CommitKnown(ctx, expectedNewRoot)
		} else {
			// Skip known root checks -- only for use in benchmarks.
			_, r, err = tree.Commit(ctx, root.Namespace, expectedNewRoot.Version)
		}
		switch err {
		case nil:
		case mkvs.ErrKnownRootMismatch:
			return nil, ErrExpectedRootMismatch
		default:
			return nil, err
		}
	}

	return &r, nil
}

func (rc *RootCache) getApplyLock(root, expectedNewRoot Root) *sync.Mutex {
	// Lock the Apply call based on (oldRoot, expectedNewRoot), so that when
	// multiple executor committees commit the same write logs, we only write
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

func (rc *RootCache) HasRoot(root Root) bool {
	return rc.localDB.HasRoot(root)
}

func NewRootCache(
	localDB nodedb.NodeDB,
	remoteSyncer syncer.ReadSyncer,
	applyLockLRUSlots uint64,
	insecureSkipChecks bool,
) (*RootCache, error) {
	applyLocks, err := lru.New(lru.Capacity(applyLockLRUSlots, false))
	if err != nil {
		return nil, fmt.Errorf("storage/rootcache: failed to create applyLocks: %w", err)
	}

	// When we implement a caching client again, we want to persist
	// everything that we obtain from the remote syncer in our local
	// database.
	persistEverything := mkvs.PersistEverythingFromSyncer(remoteSyncer != nil)

	return &RootCache{
		localDB:            localDB,
		remoteSyncer:       remoteSyncer,
		insecureSkipChecks: insecureSkipChecks,
		applyLocks:         applyLocks,
		persistEverything:  persistEverything,
	}, nil
}
