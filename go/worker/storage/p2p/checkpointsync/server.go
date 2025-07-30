package checkpointsync

import (
	"bytes"
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

type service struct {
	backend api.Backend
}

func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (any, error) {
	switch method {
	case MethodGetCheckpoints:
		var rq GetCheckpointsRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.handleGetCheckpoints(ctx, &rq)
	case MethodGetCheckpointChunk:
		var rq GetCheckpointChunkRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.handleGetCheckpointChunk(ctx, &rq)
	default:
		return nil, rpc.ErrMethodNotSupported
	}
}

func (s *service) handleGetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) (*GetCheckpointsResponse, error) {
	cps, err := s.backend.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{
		Version: request.Version,
	})
	if err != nil {
		return nil, err
	}

	return &GetCheckpointsResponse{
		Checkpoints: cps,
	}, nil
}

func (s *service) handleGetCheckpointChunk(ctx context.Context, request *GetCheckpointChunkRequest) (*GetCheckpointChunkResponse, error) {
	// Consider using stream resource manager to track buffer use.
	var buf bytes.Buffer
	err := s.backend.GetCheckpointChunk(ctx, &checkpoint.ChunkMetadata{
		Version: request.Version,
		Root:    request.Root,
		Index:   request.Index,
		Digest:  request.Digest,
	}, &buf)
	if err != nil {
		return nil, err
	}

	return &GetCheckpointChunkResponse{
		Chunk: buf.Bytes(),
	}, nil
}

// NewServer creates a new checkpoint sync protocol server.
func NewServer(chainContext string, runtimeID common.Namespace, backend api.Backend) rpc.Server {
	return rpc.NewServer(ProtocolID(chainContext, runtimeID), &service{backend})
}
