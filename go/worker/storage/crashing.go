package storage

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
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
	api.LocalBackend
}

func (w *crashingWrapper) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.LocalBackend.SyncGet(ctx, request)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.LocalBackend.SyncGetPrefixes(ctx, request)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	crash.Here(crashPointReadBefore)
	res, err := w.LocalBackend.SyncIterate(ctx, request)
	crash.Here(crashPointReadAfter)
	return res, err
}

func (w *crashingWrapper) Apply(ctx context.Context, request *api.ApplyRequest) error {
	crash.Here(crashPointWriteBefore)
	err := w.LocalBackend.Apply(ctx, request)
	crash.Here(crashPointWriteAfter)
	return err
}

func newCrashingWrapper(base api.LocalBackend) api.LocalBackend {
	return &crashingWrapper{
		LocalBackend: base,
	}
}
