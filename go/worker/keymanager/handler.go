package keymanager

import (
	"context"
	"errors"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

var (
	errEndpointNotSupported = errors.New("worker/keymanager: RPC endpoint not supported")
	errMethodNotSupported   = errors.New("worker/keymanager: method not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	sync.Mutex

	w            *Worker
	remoteClient *committeeCommon.KeyManagerClientWrapper
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
	// RPC.
	if body.HostRPCCallRequest != nil {
		switch body.HostRPCCallRequest.Endpoint {
		case runtimeKeymanager.EnclaveRPCEndpoint:
			// Call into the remote key manager.
			rsp, err := h.remoteClient.CallEnclave(ctx, body.HostRPCCallRequest.Request, body.HostRPCCallRequest.PeerFeedback)
			if err != nil {
				return nil, err
			}
			return &protocol.Body{HostRPCCallResponse: &protocol.HostRPCCallResponse{
				Response: cbor.FixSliceForSerde(rsp),
			}}, nil
		default:
			return nil, errEndpointNotSupported
		}
	}

	return nil, errMethodNotSupported
}

func newHostHandler(w *Worker, commonWorker *workerCommon.Worker, localStorage localstorage.LocalStorage) protocol.Handler {
	remoteClient := committeeCommon.NewKeyManagerClientWrapper(commonWorker.P2P, commonWorker.Consensus, w.logger)
	runtimeID := w.runtime.ID()
	remoteClient.SetKeyManagerID(&runtimeID)

	return &hostHandler{
		w:            w,
		remoteClient: remoteClient,
		localStorage: localStorage,
	}
}
