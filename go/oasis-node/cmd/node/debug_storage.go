package node

import (
	"context"
	"io"

	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

type debugStorage struct {
	n *Node
}

func (s *debugStorage) SyncGet(ctx context.Context, request *storage.GetRequest) (*storage.ProofResponse, error) {
	rt, err := s.n.RuntimeRegistry.GetRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().SyncGet(ctx, request)
}

func (s *debugStorage) SyncGetPrefixes(ctx context.Context, request *storage.GetPrefixesRequest) (*storage.ProofResponse, error) {
	rt, err := s.n.RuntimeRegistry.GetRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().SyncGetPrefixes(ctx, request)
}

func (s *debugStorage) SyncIterate(ctx context.Context, request *storage.IterateRequest) (*storage.ProofResponse, error) {
	rt, err := s.n.RuntimeRegistry.GetRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().SyncIterate(ctx, request)
}

func (s *debugStorage) GetDiff(ctx context.Context, request *storage.GetDiffRequest) (storage.WriteLogIterator, error) {
	rt, err := s.n.RuntimeRegistry.GetRuntime(request.StartRoot.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().GetDiff(ctx, request)
}

func (s *debugStorage) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	rt, err := s.n.RuntimeRegistry.GetRuntime(request.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().GetCheckpoints(ctx, request)
}

func (s *debugStorage) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	rt, err := s.n.RuntimeRegistry.GetRuntime(chunk.Root.Namespace)
	if err != nil {
		return err
	}
	return rt.Storage().GetCheckpointChunk(ctx, chunk, w)
}

func (s *debugStorage) Cleanup() {
}

func (s *debugStorage) Initialized() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
