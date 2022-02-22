package pub

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

type service struct {
	backend storage.Backend
}

func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (interface{}, error) {
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
func NewServer(runtimeID common.Namespace, backend storage.Backend) rpc.Server {
	return rpc.NewServer(runtimeID, StoragePubProtocolID, StoragePubProtocolVersion, &service{backend})
}
