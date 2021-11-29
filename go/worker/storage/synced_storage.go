package storage

import (
	"context"
	"fmt"
	"io"

	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	nodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/committee"
)

type syncedStorage struct {
	runtime *committee.Node
	wrapped storage.LocalBackend
}

func (s *syncedStorage) wait(ctx context.Context, root storage.Root) error {
	ch, err := s.runtime.WaitForRound(root.Version, &root)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ch:
		return nil
	}
}

func (s *syncedStorage) GetDiff(ctx context.Context, request *storage.GetDiffRequest) (storage.WriteLogIterator, error) {
	if err := s.wait(ctx, request.EndRoot); err != nil {
		return nil, fmt.Errorf("worker/storage: GetDiff to local storage failed: %w", err)
	}
	return s.wrapped.GetDiff(ctx, request)
}

func (s *syncedStorage) SyncGet(ctx context.Context, request *storage.GetRequest) (*storage.ProofResponse, error) {
	if err := s.wait(ctx, request.Tree.Root); err != nil {
		return nil, fmt.Errorf("worker/storage: SyncGet to local storage failed: %w", err)
	}
	return s.wrapped.SyncGet(ctx, request)
}

func (s *syncedStorage) SyncGetPrefixes(ctx context.Context, request *storage.GetPrefixesRequest) (*storage.ProofResponse, error) {
	if err := s.wait(ctx, request.Tree.Root); err != nil {
		return nil, fmt.Errorf("worker/storage: SyncGetPrefixes to local storage failed: %w", err)
	}
	return s.wrapped.SyncGetPrefixes(ctx, request)
}

func (s *syncedStorage) SyncIterate(ctx context.Context, request *storage.IterateRequest) (*storage.ProofResponse, error) {
	if err := s.wait(ctx, request.Tree.Root); err != nil {
		return nil, fmt.Errorf("worker/storage: SyncIterate to local storage failed: %w", err)
	}
	return s.wrapped.SyncIterate(ctx, request)
}

func (s *syncedStorage) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	return s.wrapped.GetCheckpoints(ctx, request)
}

func (s *syncedStorage) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	return s.wrapped.GetCheckpointChunk(ctx, chunk, w)
}

func (s *syncedStorage) Apply(ctx context.Context, request *storage.ApplyRequest) error {
	return s.wrapped.Apply(ctx, request)
}

func (s *syncedStorage) Checkpointer() checkpoint.CreateRestorer {
	return s.wrapped.Checkpointer()
}

func (s *syncedStorage) Cleanup() {
	s.wrapped.Cleanup()
}

func (s *syncedStorage) Initialized() <-chan struct{} {
	return s.wrapped.Initialized()
}

func (s *syncedStorage) NodeDB() nodedb.NodeDB {
	return s.wrapped.NodeDB()
}

// Implements storage.WrappedLocalBackend.
func (s *syncedStorage) Unwrap() storage.LocalBackend {
	return s.wrapped
}

func newSyncedLocalStorage(runtime *committee.Node, backend storage.LocalBackend) storage.LocalBackend {
	return &syncedStorage{
		runtime: runtime,
		wrapped: backend,
	}
}
