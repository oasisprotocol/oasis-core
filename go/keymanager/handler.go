package keymanager

import (
	"context"
	"errors"

	"github.com/opentracing/opentracing-go"

	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

var (
	errMethodNotSupported = errors.New("method not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	storage storage.Backend
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

	return nil, errMethodNotSupported
}

func newHostHandler(storage storage.Backend) protocol.Handler {
	return &hostHandler{storage}
}
