package storage

import (
	"context"

	"github.com/oasislabs/ekiden/go/common"
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

func (w *crashingWrapper) GetSubtree(ctx context.Context, root api.Root, id api.NodeID, maxDepth api.DepthType) (*api.Subtree, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.GetSubtree(ctx, root, id, maxDepth)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) GetPath(ctx context.Context, root api.Root, key api.Key, startDepth api.DepthType) (*api.Subtree, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.GetPath(ctx, root, key, startDepth)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) GetNode(ctx context.Context, root api.Root, id api.NodeID) (api.Node, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.GetNode(ctx, root, id)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) Apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog api.WriteLog,
) ([]*api.Receipt, error) {
	crash.Here(crashPointWriteBefore)
	res, err := w.Backend.Apply(ctx, ns, srcRound, srcRoot, dstRound, dstRoot, writeLog)
	crash.Here(crashPointWriteAfter)
	return res, err
}

func (w *crashingWrapper) ApplyBatch(
	ctx context.Context,
	ns common.Namespace,
	dstRound uint64,
	ops []api.ApplyOp,
) ([]*api.Receipt, error) {
	crash.Here(crashPointWriteBefore)
	res, err := w.Backend.ApplyBatch(ctx, ns, dstRound, ops)
	crash.Here(crashPointWriteAfter)
	return res, err
}

func newCrashingWrapper(base api.Backend) api.Backend {
	return &crashingWrapper{
		Backend: base,
	}
}
