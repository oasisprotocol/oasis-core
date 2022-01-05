package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	nodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

// RootCache is a LRU based tree cache.
type RootCache struct {
	localDB nodedb.NodeDB
}

// GetTree gets a tree entry from the cache by the root iff present, or creates
// a new tree with the specified root in the node database.
func (rc *RootCache) GetTree(ctx context.Context, root Root) (mkvs.Tree, error) {
	return mkvs.NewWithRoot(nil, rc.localDB, root), nil
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

	r := expectedNewRoot.Hash

	// Check if we already have the expected new root in our local DB.
	if !rc.localDB.HasRoot(expectedNewRoot) {
		// We don't, apply operations.
		tree := mkvs.NewWithRoot(nil, rc.localDB, root)
		defer tree.Close()

		if err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog)); err != nil {
			return nil, err
		}

		_, err := tree.CommitKnown(ctx, expectedNewRoot)
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

func (rc *RootCache) HasRoot(root Root) bool {
	return rc.localDB.HasRoot(root)
}

func NewRootCache(localDB nodedb.NodeDB) (*RootCache, error) {
	return &RootCache{
		localDB: localDB,
	}, nil
}
