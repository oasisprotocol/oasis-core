package keymanager

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

var (
	errMethodNotSupported = errors.New("method not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	runtimeID signature.PublicKey

	localStorage *host.LocalStorage
}

func (h *hostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
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

func newHostHandler(localStorage *host.LocalStorage) protocol.Handler {
	var tmpRuntimeID signature.PublicKey
	_ = tmpRuntimeID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	return &hostHandler{tmpRuntimeID, localStorage}
}
