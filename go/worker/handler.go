package worker

import (
	"context"
	"errors"

	"github.com/opentracing/opentracing-go"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/keymanager"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/host/protocol"
)

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("RPC endpoint not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	runtimeID signature.PublicKey

	storage      storage.Backend
	keyManager   *keymanager.KeyManager
	localStorage *localStorage
}

func (h *hostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	// RPC.
	if body.HostRPCCallRequest != nil {
		switch body.HostRPCCallRequest.Endpoint {
		case protocol.EndpointKeyManager:
			// Call into the remote key manager.
			res, err := h.keyManager.CallRemote(ctx, h.runtimeID, body.HostRPCCallRequest.Request)
			if err != nil {
				return nil, err
			}
			return &protocol.Body{HostRPCCallResponse: &protocol.HostRPCCallResponse{
				Response: cbor.FixSliceForSerde(res),
			}}, nil
		default:
			return nil, errEndpointNotSupported
		}
	}
	// Storage.
	if body.HostStorageGetRequest != nil {
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.Get(key)",
			opentracing.Tag{Key: "key", Value: body.HostStorageGetRequest.Key},
		)
		defer span.Finish()

		value, err := h.storage.Get(sctx, body.HostStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostStorageGetResponse: &protocol.HostStorageGetResponse{Value: value}}, nil
	}
	if body.HostStorageGetBatchRequest != nil {
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.GetBatch(key)",
			opentracing.Tag{Key: "key", Value: body.HostStorageGetRequest.Key},
		)
		defer span.Finish()

		values, err := h.storage.GetBatch(sctx, body.HostStorageGetBatchRequest.Keys)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostStorageGetBatchResponse: &protocol.HostStorageGetBatchResponse{Values: values}}, nil
	}
	// Local storage.
	if body.HostLocalStorageGetRequest != nil {
		value, err := h.localStorage.Get(h.runtimeID, body.HostLocalStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageGetResponse: &protocol.HostLocalStorageGetResponse{Value: value}}, nil
	}
	if body.HostLocalStorageSetRequest != nil {
		if err := h.localStorage.Set(h.runtimeID, body.HostLocalStorageSetRequest.Key, body.HostLocalStorageSetRequest.Value); err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageSetResponse: &protocol.Empty{}}, nil
	}

	return nil, errMethodNotSupported
}

func newHostHandler(runtimeID signature.PublicKey, storage storage.Backend, keyManager *keymanager.KeyManager, localStorage *localStorage) protocol.Handler {
	return &hostHandler{runtimeID, storage, keyManager, localStorage}
}
