package storage

import (
	"context"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/grpc/auth"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

var (
	_ api.Backend     = (*storageService)(nil)
	_ auth.ServerAuth = (*storageService)(nil)
)

// storageService is the service exposed to external clients via gRPC.
type storageService struct {
	w       *Worker
	storage api.Backend
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

func (s *storageService) GetDiff(ctx context.Context, request *api.GetDiffRequest) (api.WriteLogIterator, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.GetDiff(ctx, request)
}

func (s *storageService) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return s.storage.GetCheckpoints(ctx, request)
}

func (s *storageService) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	if err := s.ensureInitialized(ctx); err != nil {
		return err
	}
	return s.storage.GetCheckpointChunk(ctx, chunk, w)
}

func (s *storageService) Cleanup() {
}

func (s *storageService) Initialized() <-chan struct{} {
	return s.storage.Initialized()
}
