package diffsync

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
)

type service struct {
	backend api.Backend
}

func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (any, error) {
	switch method {
	case MethodGetDiff:
		var rq GetDiffRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.handleGetDiff(ctx, &rq)
	default:
		return nil, rpc.ErrMethodNotSupported
	}
}

func (s *service) handleGetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, error) {
	it, err := s.backend.GetDiff(ctx, &api.GetDiffRequest{
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

// NewServer creates a new storage diff protocol server.
func NewServer(chainContext string, runtimeID common.Namespace, backend api.Backend) rpc.Server {
	return rpc.NewServer(protocol.NewRuntimeProtocolID(chainContext, runtimeID, DiffSyncProtocolID, DiffSyncProtocolVersion), &service{backend})
}
