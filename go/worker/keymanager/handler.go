package keymanager

import (
	"context"
	"errors"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/client"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
)

var (
	errEndpointNotSupported = errors.New("worker/keymanager: RPC endpoint not supported")
	errMethodNotSupported   = errors.New("worker/keymanager: method not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	sync.Mutex

	w            *Worker
	remoteClient *client.Client
	localStorage localstorage.LocalStorage
}

func (h *hostHandler) initRemoteClient(commonWorker *workerCommon.Worker) {
	remoteClient, err := client.New(h.w.ctx, h.w.runtime, commonWorker.Consensus, commonWorker.Identity)
	if err != nil {
		h.w.logger.Error("failed to create remote client",
			"err", err,
		)
		return
	}

	select {
	case <-h.w.ctx.Done():
		h.w.logger.Error("failed to wait for key manager",
			"err", h.w.ctx.Err(),
		)
	case <-remoteClient.Initialized():
		h.Lock()
		defer h.Unlock()
		h.remoteClient = remoteClient
	}
}

func (h *hostHandler) getRemoteClient() (*client.Client, error) {
	h.Lock()
	defer h.Unlock()

	if h.remoteClient != nil {
		return h.remoteClient, nil
	}

	return nil, errEndpointNotSupported
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
		case api.EnclaveRPCEndpoint:
			remoteClient, err := h.getRemoteClient()
			if err != nil {
				return nil, err
			}

			// Call into the remote key manager.
			res, err := remoteClient.CallRemote(ctx, body.HostRPCCallRequest.Request)
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

	return nil, errMethodNotSupported
}

func newHostHandler(w *Worker, commonWorker *workerCommon.Worker, localStorage localstorage.LocalStorage) protocol.Handler {
	h := &hostHandler{
		w:            w,
		localStorage: localStorage,
	}

	go h.initRemoteClient(commonWorker)

	return h
}
