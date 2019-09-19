package common

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentracing/opentracing-go"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/client"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("RPC endpoint not supported")

	_ protocol.Handler = (*runtimeHostHandler)(nil)
)

type runtimeHostHandler struct {
	runtimeID signature.PublicKey

	storage      storage.Backend
	keyManager   *keymanager.Client
	localStorage *host.LocalStorage
}

func (h *runtimeHostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
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

// NewRuntimeHostHandler creates a worker host handler for runtime execution.
func NewRuntimeHostHandler(
	runtimeID signature.PublicKey,
	storage storage.Backend,
	keyManager *keymanager.Client,
	localStorage *host.LocalStorage,
) protocol.Handler {
	return &runtimeHostHandler{runtimeID, storage, keyManager, localStorage}
}

// RuntimeHostWorker provides methods for workers that need to host runtimes.
type RuntimeHostWorker struct {
	commonWorker *Worker
}

// NewRuntimeWorkerHost creates a new worker host for the given runtime.
func (rw *RuntimeHostWorker) NewRuntimeWorkerHost(role node.RolesMask, id signature.PublicKey) (h host.Host, err error) {
	cfg := rw.commonWorker.GetConfig().RuntimeHost
	rtCfg, ok := cfg.Runtimes[id.ToMapKey()]
	if !ok {
		return nil, fmt.Errorf("runtime host: unknown runtime: %s", id)
	}

	hostCfg := &host.Config{
		Role:          role,
		ID:            rtCfg.ID,
		WorkerBinary:  cfg.Loader,
		RuntimeBinary: rtCfg.Binary,
		TEEHardware:   rtCfg.TEEHardware,
		IAS:           rw.commonWorker.IAS,
		MessageHandler: NewRuntimeHostHandler(
			rtCfg.ID,
			rw.commonWorker.Storage,
			rw.commonWorker.KeyManager,
			rw.commonWorker.LocalStorage,
		),
	}

	switch strings.ToLower(cfg.Backend) {
	case host.BackendSandboxed:
		h, err = host.NewHost(hostCfg)
	case host.BackendUnconfined:
		hostCfg.NoSandbox = true
		h, err = host.NewHost(hostCfg)
	case host.BackendMock:
		h, err = host.NewMockHost()
	default:
		err = fmt.Errorf("runtime host: unsupported worker host backend: '%v'", cfg.Backend)
	}

	return
}

// NewRuntimeHostWorker creates a new runtime host worker.
func NewRuntimeHostWorker(commonWorker *Worker) (*RuntimeHostWorker, error) {
	cfg := commonWorker.GetConfig().RuntimeHost
	if cfg == nil {
		return nil, fmt.Errorf("runtime host: missing configuration")
	}
	if cfg.Loader == "" && cfg.Backend != host.BackendMock {
		return nil, fmt.Errorf("runtime host: no runtime loader binary configured and backend not host.BackendMock")
	}
	if len(cfg.Runtimes) == 0 {
		return nil, fmt.Errorf("runtime host: no runtimes configured")
	}

	return &RuntimeHostWorker{commonWorker: commonWorker}, nil
}
