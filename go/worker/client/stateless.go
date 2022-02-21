package client

import (
	"context"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
	storagePub "github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/pub"
)

type statelessStorage struct {
	rpc storagePub.Client
}

func (s *statelessStorage) SyncGet(ctx context.Context, request *storage.GetRequest) (*storage.ProofResponse, error) {
	rsp, _, err := s.rpc.Get(ctx, request)
	return rsp, err
}

func (s *statelessStorage) SyncGetPrefixes(ctx context.Context, request *storage.GetPrefixesRequest) (*storage.ProofResponse, error) {
	rsp, _, err := s.rpc.GetPrefixes(ctx, request)
	return rsp, err
}

func (s *statelessStorage) SyncIterate(ctx context.Context, request *storage.IterateRequest) (*storage.ProofResponse, error) {
	rsp, _, err := s.rpc.Iterate(ctx, request)
	return rsp, err
}

func (s *statelessStorage) GetDiff(ctx context.Context, request *storage.GetDiffRequest) (storage.WriteLogIterator, error) {
	return nil, storage.ErrUnsupported
}

func (s *statelessStorage) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	return nil, storage.ErrUnsupported
}

func (s *statelessStorage) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	return storage.ErrUnsupported
}

func (s *statelessStorage) Cleanup() {
}

func (s *statelessStorage) Initialized() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// NewStatelessStorage creates a stateless storage backend that uses the P2P transport and the
// storagepub protocol to query storage state.
func NewStatelessStorage(p2p rpc.P2P, runtimeID common.Namespace) storage.Backend {
	return &statelessStorage{
		rpc: storagePub.NewClient(p2p, runtimeID),
	}
}
