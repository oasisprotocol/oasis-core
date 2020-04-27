package committee

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentracing/opentracing-go"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	keymanagerApi "github.com/oasislabs/oasis-core/go/keymanager/api"
	keymanagerClient "github.com/oasislabs/oasis-core/go/keymanager/client"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/runtime/host/protocol"
	"github.com/oasislabs/oasis-core/go/runtime/localstorage"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
)

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("RPC endpoint not supported")
)

// computeRuntimeHostHandler is a runtime host handler suitable for compute runtimes.
type computeRuntimeHostHandler struct {
	runtime runtimeRegistry.Runtime

	storage          storage.Backend
	keyManager       keymanagerApi.Backend
	keyManagerClient *keymanagerClient.Client
	localStorage     localstorage.LocalStorage
}

func (h *computeRuntimeHostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	// Key manager.
	if body.HostKeyManagerPolicyRequest != nil {
		rt, err := h.runtime.RegistryDescriptor(ctx)
		if err != nil {
			return nil, fmt.Errorf("runtime host: failed to obtain runtime descriptor: %w", err)
		}
		if rt.KeyManager == nil {
			return nil, errors.New("runtime has no key manager")
		}
		status, err := h.keyManager.GetStatus(ctx, &registry.NamespaceQuery{
			ID:     *rt.KeyManager,
			Height: consensus.HeightLatest,
		})
		if err != nil {
			return nil, err
		}

		var policy keymanagerApi.SignedPolicySGX
		if status != nil && status.Policy != nil {
			policy = *status.Policy
		}
		return &protocol.Body{HostKeyManagerPolicyResponse: &protocol.HostKeyManagerPolicyResponse{
			SignedPolicyRaw: cbor.Marshal(policy),
		}}, nil
	}
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
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.Sync")
		defer span.Finish()

		var rsp *storage.ProofResponse
		var err error
		switch {
		case rq.SyncGet != nil:
			rsp, err = h.storage.SyncGet(sctx, rq.SyncGet)
		case rq.SyncGetPrefixes != nil:
			rsp, err = h.storage.SyncGetPrefixes(sctx, rq.SyncGetPrefixes)
		case rq.SyncIterate != nil:
			rsp, err = h.storage.SyncIterate(sctx, rq.SyncIterate)
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

// Implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostHandler() protocol.Handler {
	return &computeRuntimeHostHandler{
		n.Runtime,
		n.Runtime.Storage(),
		n.KeyManager,
		n.KeyManagerClient,
		n.Runtime.LocalStorage(),
	}
}
