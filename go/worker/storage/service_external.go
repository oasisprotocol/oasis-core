package storage

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/common/grpc/auth"
	"github.com/oasislabs/oasis-core/go/common/grpc/policy"
	"github.com/oasislabs/oasis-core/go/storage/api"
)

var (
	_ api.Backend     = (*storageService)(nil)
	_ auth.ServerAuth = (*storageService)(nil)

	errDebugRejectUpdates = errors.New("storage: (debug) rejecting update operations")
)

// storageService is the service exposed to external clients via gRPC.
type storageService struct {
	w       *Worker
	storage api.Backend

	debugRejectUpdates bool
}

func (s *storageService) AuthFunc(ctx context.Context, fullMethodName string, req interface{}) error {
	return policy.GRPCAuthenticationFunction(s.w.grpcPolicy)(ctx, fullMethodName, req)
}

func (s *storageService) ensureInitialized(ctx context.Context) error {
	select {
	case <-s.Initialized():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *storageService) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.SyncGet(ctx, request)
}

func (s *storageService) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.SyncGetPrefixes(ctx, request)
}

func (s *storageService) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.SyncIterate(ctx, request)
}

func (s *storageService) Apply(ctx context.Context, request *api.ApplyRequest) ([]*api.Receipt, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	if s.debugRejectUpdates {
		return nil, errDebugRejectUpdates
	}

	return s.storage.Apply(ctx, request)
}

func (s *storageService) ApplyBatch(ctx context.Context, request *api.ApplyBatchRequest) ([]*api.Receipt, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	if s.debugRejectUpdates {
		return nil, errDebugRejectUpdates
	}

	return s.storage.ApplyBatch(ctx, request)
}

func (s *storageService) Merge(ctx context.Context, request *api.MergeRequest) ([]*api.Receipt, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	if s.debugRejectUpdates {
		return nil, errDebugRejectUpdates
	}

	return s.storage.Merge(ctx, request)
}

func (s *storageService) MergeBatch(ctx context.Context, request *api.MergeBatchRequest) ([]*api.Receipt, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	if s.debugRejectUpdates {
		return nil, errDebugRejectUpdates
	}

	return s.storage.MergeBatch(ctx, request)
}

func (s *storageService) GetDiff(ctx context.Context, request *api.GetDiffRequest) (api.WriteLogIterator, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.GetDiff(ctx, request)
}

func (s *storageService) GetCheckpoint(ctx context.Context, request *api.GetCheckpointRequest) (api.WriteLogIterator, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.GetCheckpoint(ctx, request)
}

func (s *storageService) Cleanup() {
}

func (s *storageService) Initialized() <-chan struct{} {
	return s.storage.Initialized()
}
