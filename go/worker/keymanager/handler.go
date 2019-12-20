package keymanager

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/runtime/localstorage"
	"github.com/oasislabs/oasis-core/go/worker/common/host/protocol"
)

var (
	errMethodNotSupported = errors.New("worker/keymanager: method not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	w            *Worker
	localStorage localstorage.LocalStorage
}

func (h *hostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	// Local storage.
	if body.HostLocalStorageGetRequest != nil {
		value, err := h.localStorage.Get(body.HostLocalStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageGetResponse: &protocol.HostLocalStorageGetResponse{Value: value}}, nil
	}
	if body.HostLocalStorageSetRequest != nil {
		if err := h.localStorage.Set(body.HostLocalStorageSetRequest.Key, body.HostLocalStorageSetRequest.Value); err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageSetResponse: &protocol.Empty{}}, nil
	}

	return nil, errMethodNotSupported
}

func newHostHandler(w *Worker, localStorage localstorage.LocalStorage) protocol.Handler {
	return &hostHandler{w, localStorage}
}
