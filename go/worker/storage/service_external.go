package storage

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/storage/api"
)

// storageService is the service exposed to external clients via gRPC.
type storageService struct {
	w       *Worker
	storage api.Backend

	debugRejectUpdates bool
}

func (s *storageService) checkUpdateAllowed(ctx context.Context, method string, ns common.Namespace) error {
	if s.debugRejectUpdates {
		return errors.New("storage: rejecting update operations")
	}
	if err := s.w.grpcPolicy.CheckAccessAllowed(ctx, accessctl.Action(method), ns); err != nil {
		return err
	}
	return nil
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
	if err := s.checkUpdateAllowed(ctx, "Apply", request.Namespace); err != nil {
		return nil, err
	}
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.Apply(ctx, request)
}

func (s *storageService) ApplyBatch(ctx context.Context, request *api.ApplyBatchRequest) ([]*api.Receipt, error) {
	if err := s.checkUpdateAllowed(ctx, "ApplyBatch", request.Namespace); err != nil {
		return nil, err
	}
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.ApplyBatch(ctx, request)
}

func (s *storageService) Merge(ctx context.Context, request *api.MergeRequest) ([]*api.Receipt, error) {
	if err := s.checkUpdateAllowed(ctx, "Merge", request.Namespace); err != nil {
		return nil, err
	}
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.Merge(ctx, request)
}

func (s *storageService) MergeBatch(ctx context.Context, request *api.MergeBatchRequest) ([]*api.Receipt, error) {
	if err := s.checkUpdateAllowed(ctx, "MergeBatch", request.Namespace); err != nil {
		return nil, err
	}
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.MergeBatch(ctx, request)
}

func (s *storageService) GetDiff(ctx context.Context, request *api.GetDiffRequest) (api.WriteLogIterator, error) {
	if err := s.w.grpcPolicy.CheckAccessAllowed(ctx, accessctl.Action("GetDiff"), request.StartRoot.Namespace); err != nil {
		return nil, err
	}
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.GetDiff(ctx, request)
}

func (s *storageService) GetCheckpoint(ctx context.Context, request *api.GetCheckpointRequest) (api.WriteLogIterator, error) {
	if err := s.w.grpcPolicy.CheckAccessAllowed(ctx, accessctl.Action("GetCheckpoint"), request.Root.Namespace); err != nil {
		return nil, err
	}
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
