package storage

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/crash"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	crashPointReadBefore  = "storage.read.before"
	crashPointReadAfter   = "storage.read.after"
	crashPointWriteBefore = "storage.write.before"
	crashPointWriteAfter  = "storage.write.after"
)

func init() {
	crash.RegisterCrashPoints(
		crashPointReadBefore,
		crashPointReadAfter,
		crashPointWriteBefore,
		crashPointWriteAfter,
	)
}

type crashingWrapper struct {
	api.Backend
}

func (w *crashingWrapper) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.GetSubtree(ctx, root, id, maxDepth)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.GetPath(ctx, root, key, startDepth)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.GetNode(ctx, root, id)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.GetValue(ctx, root, id)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) ([]*api.MKVSReceipt, error) {
	crash.Here(crashPointWriteBefore)
	res, err := w.Backend.Apply(ctx, root, expectedNewRoot, log)
	crash.Here(crashPointWriteAfter)
	return res, err
}

func newCrashingWrapper(base api.Backend) api.Backend {
	return &crashingWrapper{
		Backend: base,
	}
}
