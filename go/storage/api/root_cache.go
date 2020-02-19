package api

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cache/lru"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/writelog"
)

// RootCache is a LRU based tree cache.
type RootCache struct {
	localDB      nodedb.NodeDB
	remoteSyncer syncer.ReadSyncer

	insecureSkipChecks bool

	applyLocks      *lru.Cache
	applyLocksGuard sync.Mutex

	persistEverything urkel.Option
}

// GetTree gets a tree entry from the cache by the root iff present, or creates
// a new tree with the specified root in the node database.
func (rc *RootCache) GetTree(ctx context.Context, root Root) (urkel.Tree, error) {
	return urkel.NewWithRoot(rc.remoteSyncer, rc.localDB, root, rc.persistEverything), nil
}

// Merge performs a 3-way merge operation between the specified roots and returns
// a receipt for the merged root.
func (rc *RootCache) Merge(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	base hash.Hash,
	others []hash.Hash,
) (*hash.Hash, error) {
	if len(others) == 0 {
		// No other roots passed, no reason to call the operation.
		return nil, ErrNoMergeRoots
	}

	// Make sure that all roots exist in storage before doing any work.
	if !rc.localDB.HasRoot(Root{Namespace: ns, Round: round, Hash: base}) {
		return nil, ErrRootNotFound
	}
	for _, rootHash := range others {
		if !rc.localDB.HasRoot(Root{Namespace: ns, Round: round + 1, Hash: rootHash}) {
			return nil, ErrRootNotFound
		}
	}

	if len(others) == 1 {
		// Fast path: nothing to merge, just return the only root.
		return &others[0], nil
	}

	// Start with the first root.
	// TODO: WithStorageProof.
	tree := urkel.NewWithRoot(nil, rc.localDB, Root{Namespace: ns, Round: round + 1, Hash: others[0]})
	defer tree.Close()

	// Apply operations from all roots.
	baseRoot := Root{Namespace: ns, Round: round, Hash: base}
	for _, rootHash := range others[1:] {
		it, err := rc.localDB.GetWriteLog(ctx, baseRoot, Root{Namespace: ns, Round: round + 1, Hash: rootHash})
		if err != nil {
			return nil, fmt.Errorf("storage/rootcache: failed to read write log: %w", err)
		}

		if err = tree.ApplyWriteLog(ctx, it); err != nil {
			return nil, fmt.Errorf("storage/rootcache: failed to apply write log: %w", err)
		}
	}

	var mergedRoot hash.Hash
	var err error
	if _, mergedRoot, err = tree.Commit(ctx, ns, round+1); err != nil {
		return nil, fmt.Errorf("storage/rootcache: failed to commit write log: %w", err)
	}

	return &mergedRoot, nil
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
		return nil, ErrRootMustFollowOld
	}

	mu := rc.getApplyLock(root, expectedNewRoot)
	mu.Lock()
	defer mu.Unlock()

	var r hash.Hash

	// Check if we already have the expected new root in our local DB.
	if rc.localDB.HasRoot(expectedNewRoot) {
		// We do, don't apply anything.
		r = dstRoot
	} else {
		// We don't, apply operations.
		tree := urkel.NewWithRoot(rc.remoteSyncer, rc.localDB, root, rc.persistEverything)
		defer tree.Close()

		if err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog)); err != nil {
			return nil, err
		}

		var err error
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
	persistEverything := urkel.PersistEverythingFromSyncer(remoteSyncer != nil)

	return &RootCache{
		localDB:            localDB,
		remoteSyncer:       remoteSyncer,
		insecureSkipChecks: insecureSkipChecks,
		applyLocks:         applyLocks,
		persistEverything:  persistEverything,
	}, nil
}
