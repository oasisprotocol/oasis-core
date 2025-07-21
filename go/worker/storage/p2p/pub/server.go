package pub

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

type service struct {
	backend storage.Backend
}

func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (any, error) {
	switch method {
	case MethodGet:
		var rq GetRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.backend.SyncGet(ctx, &rq)
	case MethodGetPrefixes:
		var rq GetPrefixesRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.backend.SyncGetPrefixes(ctx, &rq)
	case MethodIterate:
		var rq IterateRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.backend.SyncIterate(ctx, &rq)
	default:
		return nil, rpc.ErrMethodNotSupported
	}
}

// NewServer creates a new storage pub protocol server.
func NewServer(chainContext string, runtimeID common.Namespace, backend storage.Backend) rpc.Server {
	return rpc.NewServer(ProtocolID(chainContext, runtimeID), &service{backend})
}
