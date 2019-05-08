package keymanager

import (
	"context"
	"errors"

	"github.com/opentracing/opentracing-go"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

var (
	errMethodNotSupported = errors.New("method not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	runtimeID signature.PublicKey

	storage      storage.Backend
	localStorage *host.LocalStorage
}

func (h *hostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
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

func newHostHandler(storage storage.Backend, localStorage *host.LocalStorage) protocol.Handler {
	var tmpRuntimeID signature.PublicKey
	_ = tmpRuntimeID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	return &hostHandler{tmpRuntimeID, storage, localStorage}
}
