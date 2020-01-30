package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/grpc/auth"
	"github.com/oasislabs/oasis-core/go/common/grpc/policy"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
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

func (s *storageService) getConfig(ctx context.Context, ns common.Namespace) (*registry.StorageParameters, error) {
	rt, err := s.w.commonWorker.RuntimeRegistry.GetRuntime(ns)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to get runtime %s: %w", ns, err)
	}

	rtDesc, err := rt.RegistryDescriptor(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to get runtime %s configuration: %w", ns, err)
	}
	return &rtDesc.Storage, nil
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

	// Limit maximum number of entries in a write log.
	cfg, err := s.getConfig(ctx, request.Namespace)
	if err != nil {
		return nil, err
	}
	if uint64(len(request.WriteLog)) > cfg.MaxApplyWriteLogEntries {
		return nil, api.ErrLimitReached
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

	// Limit maximum number of operations in a batch.
	cfg, err := s.getConfig(ctx, request.Namespace)
	if err != nil {
		return nil, err
	}
	if uint64(len(request.Ops)) > cfg.MaxApplyOps {
		return nil, api.ErrLimitReached
	}
	// Limit maximum number of entries in a write log.
	for _, op := range request.Ops {
		if uint64(len(op.WriteLog)) > cfg.MaxApplyWriteLogEntries {
			return nil, api.ErrLimitReached
		}
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

	// Limit maximum number of roots to merge.
	cfg, err := s.getConfig(ctx, request.Namespace)
	if err != nil {
		return nil, err
	}
	if uint64(len(request.Others)) > cfg.MaxMergeRoots {
		return nil, api.ErrLimitReached
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

	// Limit maximum number of operations in a batch.
	cfg, err := s.getConfig(ctx, request.Namespace)
	if err != nil {
		return nil, err
	}
	if uint64(len(request.Ops)) > cfg.MaxMergeOps {
		return nil, api.ErrLimitReached
	}
	// Limit maximum number of roots to merge.
	for _, op := range request.Ops {
		if uint64(len(op.Others)) > cfg.MaxMergeRoots {
			return nil, api.ErrLimitReached
		}
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
