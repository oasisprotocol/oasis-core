package committee

import (
	"context"
	"errors"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanagerApi "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	keymanagerClient "github.com/oasisprotocol/oasis-core/go/keymanager/client"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("endpoint not supported")
)

// computeRuntimeHostHandler is a runtime host handler suitable for compute runtimes.
type computeRuntimeHostHandler struct {
	node    *Node
	runtime runtimeRegistry.Runtime

	storage          storage.Backend
	keyManager       keymanagerApi.Backend
	keyManagerClient *keymanagerClient.Client
	localStorage     localstorage.LocalStorage
	consensus        consensus.Backend
}

func (h *computeRuntimeHostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	// RPC.
	if body.HostRPCCallRequest != nil {
		switch body.HostRPCCallRequest.Endpoint {
		case keymanagerApi.EnclaveRPCEndpoint:
			// Call into the remote key manager.
			if h.keyManagerClient == nil {
				return nil, errEndpointNotSupported
			}
			res, err := h.keyManagerClient.CallRemote(ctx, body.HostRPCCallRequest.Request)
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
	if body.HostStorageSyncRequest != nil {
		rq := body.HostStorageSyncRequest

		var rs syncer.ReadSyncer
		switch rq.Endpoint {
		case protocol.HostStorageEndpointRuntime:
			// Runtime storage.
			rs = h.storage

			// Prioritize nodes that signed the last storage receipts.
			h.node.CrossNode.Lock()
			blk := h.node.CurrentBlock
			h.node.CrossNode.Unlock()
			if blk != nil {
				ctx = storage.WithNodePriorityHintFromSignatures(ctx, blk.Header.StorageSignatures)
			}
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

// Implements RuntimeHostHandlerFactory.
func (n *Node) GetRuntime() runtimeRegistry.Runtime {
	return n.Runtime
}

// computeRuntimeHostNotifier is a runtime host notifier suitable for compute
// runtimes.
type computeRuntimeHostNotifier struct {
	sync.Mutex

	ctx context.Context

	stopCh chan struct{}

	started    bool
	runtime    runtimeRegistry.Runtime
	host       host.Runtime
	keyManager keymanagerApi.Backend

	logger *logging.Logger
}

func (n *computeRuntimeHostNotifier) watchPolicyUpdates() {
	// Wait for the runtime.
	rt, err := n.runtime.RegistryDescriptor(n.ctx)
	if err != nil {
		n.logger.Error("failed to wait for registry descriptor",
			"err", err,
		)
		return
	}
	if rt.KeyManager == nil {
		n.logger.Info("no keymanager needed, not watching for policy updates")
		return
	}

	stCh, stSub := n.keyManager.WatchStatuses()
	defer stSub.Close()
	n.logger.Info("watching policy updates", "keymanager_runtime", rt.KeyManager)

	for {
		select {
		case <-n.ctx.Done():
			n.logger.Warn("contex canceled")
			return
		case <-n.stopCh:
			n.logger.Warn("termination requested")
			return
		case st := <-stCh:
			n.logger.Debug("got policy update", "status", st)

			// Ignore status updates if key manager is not yet known (is nil)
			// or if the status update is for a different key manager.
			if !st.ID.Equal(rt.KeyManager) {
				continue
			}

			raw := cbor.Marshal(st.Policy)
			req := &protocol.Body{RuntimeKeyManagerPolicyUpdateRequest: &protocol.RuntimeKeyManagerPolicyUpdateRequest{
				SignedPolicyRaw: raw,
			}}

			response, err := n.host.Call(n.ctx, req)
			if err != nil {
				n.logger.Error("failed dispatching key manager policy update to runtime",
					"err", err,
				)
				continue
			}
			n.logger.Debug("key manager policy updated dispatched", "response", response)
		}
	}
}

// Implements protocol.Notifier.
func (n *computeRuntimeHostNotifier) Start() error {
	n.Lock()
	defer n.Unlock()

	if n.started {
		return nil
	}
	n.started = true

	go n.watchPolicyUpdates()

	return nil
}

// Implements protocol.Notifier.
func (n *computeRuntimeHostNotifier) Stop() {
	close(n.stopCh)
}

// Implements RuntimeHostHandlerFactory.
func (n *Node) NewNotifier(ctx context.Context, host host.Runtime) protocol.Notifier {
	return &computeRuntimeHostNotifier{
		ctx:        ctx,
		stopCh:     make(chan struct{}),
		runtime:    n.Runtime,
		host:       host,
		keyManager: n.KeyManager,
		logger:     logging.GetLogger("committee/runtime-host"),
	}
}

// Implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostHandler() protocol.Handler {
	return &computeRuntimeHostHandler{
		node:             n,
		runtime:          n.Runtime,
		storage:          n.Runtime.Storage(),
		keyManager:       n.KeyManager,
		keyManagerClient: n.KeyManagerClient,
		localStorage:     n.Runtime.LocalStorage(),
		consensus:        n.Consensus,
	}
}
