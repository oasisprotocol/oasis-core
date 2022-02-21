package sync

import (
	"bytes"
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

type service struct {
	backend storage.Backend
}

func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (interface{}, error) {
	switch method {
	case MethodGetDiff:
		var rq GetDiffRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.handleGetDiff(ctx, &rq)
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

func (s *service) handleGetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, error) {
	it, err := s.backend.GetDiff(ctx, &storage.GetDiffRequest{
		StartRoot: request.StartRoot,
		EndRoot:   request.EndRoot,
	})
	if err != nil {
		return nil, err
	}

	var rsp GetDiffResponse
	for {
		more, err := it.Next()
		if err != nil {
			return nil, err
		}
		if !more {
			break
		}

		chunk, err := it.Value()
		if err != nil {
			return nil, err
		}
		rsp.WriteLog = append(rsp.WriteLog, chunk)
	}
	return &rsp, nil
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
	// TODO: Use stream resource manager to track buffer use.
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

// NewServer creates a new storage sync protocol server.
func NewServer(runtimeID common.Namespace, backend storage.Backend) rpc.Server {
	return rpc.NewServer(runtimeID, StorageSyncProtocolID, StorageSyncProtocolVersion, &service{backend})
}
