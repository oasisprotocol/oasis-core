package storage

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crash"
	"github.com/oasislabs/oasis-core/go/storage/api"
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

func (w *crashingWrapper) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.SyncGet(ctx, request)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.SyncGetPrefixes(ctx, request)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.Backend.SyncIterate(ctx, request)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) Apply(ctx context.Context, request *api.ApplyRequest) ([]*api.Receipt, error) {
	crash.Here(crashPointWriteBefore)
	res, err := w.Backend.Apply(ctx, request)
	crash.Here(crashPointWriteAfter)
	return res, err
}

func (w *crashingWrapper) ApplyBatch(ctx context.Context, request *api.ApplyBatchRequest) ([]*api.Receipt, error) {
	crash.Here(crashPointWriteBefore)
	res, err := w.Backend.ApplyBatch(ctx, request)
	crash.Here(crashPointWriteAfter)
	return res, err
}

func newCrashingWrapper(base api.Backend) api.Backend {
	return &crashingWrapper{
		Backend: base,
	}
}
