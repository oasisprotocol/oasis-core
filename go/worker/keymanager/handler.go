package keymanager

import (
	"context"
	"errors"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
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
	consensus    consensus.Backend
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
	// Storage.
	if body.HostStorageSyncRequest != nil {
		rq := body.HostStorageSyncRequest

		var rs syncer.ReadSyncer
		switch rq.Endpoint {
		case protocol.HostStorageEndpointConsensus:
			// Consensus state storage.
			rs = h.consensus.State()
		default:
			return nil, errEndpointNotSupported
		}

		var rsp *storage.ProofResponse
		var err error
		switch {
		case rq.SyncGet != nil:
			rsp, err = rs.SyncGet(ctx, rq.SyncGet)
		case rq.SyncGetPrefixes != nil:
			rsp, err = rs.SyncGetPrefixes(ctx, rq.SyncGetPrefixes)
		case rq.SyncIterate != nil:
			rsp, err = rs.SyncIterate(ctx, rq.SyncIterate)
		default:
			return nil, errMethodNotSupported
		}
		if err != nil {
			return nil, err
		}

		return &protocol.Body{HostStorageSyncResponse: &protocol.HostStorageSyncResponse{ProofResponse: rsp}}, nil
	}
	// Consensus light client.
	if body.HostFetchConsensusBlockRequest != nil {
		lb, err := h.consensus.GetLightBlock(ctx, int64(body.HostFetchConsensusBlockRequest.Height))
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostFetchConsensusBlockResponse: &protocol.HostFetchConsensusBlockResponse{
			Block: *lb,
		}}, nil
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
		consensus:    commonWorker.Consensus,
	}
}
