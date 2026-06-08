package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	nodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

// RootCache helps accessing and applying roots in the local DB.
type RootCache struct {
	localDB nodedb.NodeDB
}

// GetTree returns a tree for the given root.
func (rc *RootCache) GetTree(root Root) (mkvs.Tree, error) {
	return mkvs.NewWithRoot(nil, rc.localDB, root), nil
}

// Apply applies a write log unless the expected new root already exists locally.
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

	if rc.localDB.HasRoot(expectedNewRoot) {
		return &r, nil
	}

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
