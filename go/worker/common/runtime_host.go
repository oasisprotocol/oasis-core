package common

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentracing/opentracing-go"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	keymanagerApi "github.com/oasislabs/oasis-core/go/keymanager/api"
	keymanagerClient "github.com/oasislabs/oasis-core/go/keymanager/client"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/common/host"
	"github.com/oasislabs/oasis-core/go/worker/common/host/protocol"
)

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("RPC endpoint not supported")

	_ protocol.Handler = (*runtimeHostHandler)(nil)
	_ host.Factory     = (*runtimeWorkerHostMockFactory)(nil)
	_ host.Factory     = (*runtimeWorkerHostSandboxedFactory)(nil)
)

type runtimeHostHandler struct {
	runtime *registry.Runtime

	storage          storage.Backend
	keyManager       keymanagerApi.Backend
	keyManagerClient *keymanagerClient.Client
	localStorage     *host.LocalStorage
}

func (h *runtimeHostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	// Key manager.
	if body.HostKeyManagerPolicyRequest != nil {
		status, err := h.keyManager.GetStatus(ctx, h.runtime.KeyManager, 0)
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
		case protocol.EndpointKeyManager:
			// Call into the remote key manager.
			res, err := h.keyManagerClient.CallRemote(ctx, h.runtime.ID, body.HostRPCCallRequest.Request)
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
		value, err := h.localStorage.Get(h.runtime.ID, body.HostLocalStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageGetResponse: &protocol.HostLocalStorageGetResponse{Value: value}}, nil
	}
	if body.HostLocalStorageSetRequest != nil {
		if err := h.localStorage.Set(h.runtime.ID, body.HostLocalStorageSetRequest.Key, body.HostLocalStorageSetRequest.Value); err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageSetResponse: &protocol.Empty{}}, nil
	}

	return nil, errMethodNotSupported
}

// NewRuntimeHostHandler creates a worker host handler for runtime execution.
func NewRuntimeHostHandler(
	runtime *registry.Runtime,
	storage storage.Backend,
	keyManager keymanagerApi.Backend,
	keyManagerClient *keymanagerClient.Client,
	localStorage *host.LocalStorage,
) protocol.Handler {
	return &runtimeHostHandler{runtime, storage, keyManager, keyManagerClient, localStorage}
}

// RuntimeHostWorker provides methods for workers that need to host runtimes.
type RuntimeHostWorker struct {
	commonWorker *Worker
}

type runtimeWorkerHostMockFactory struct{}

func (f *runtimeWorkerHostMockFactory) NewWorkerHost(cfg host.Config) (host.Host, error) {
	return host.NewMockHost()
}

type runtimeWorkerHostSandboxedFactory struct {
	cfgTemplate host.Config
}

func (f *runtimeWorkerHostSandboxedFactory) NewWorkerHost(cfg host.Config) (host.Host, error) {
	// Instantiate the template with the provided configuration values.
	hostCfg := f.cfgTemplate
	hostCfg.TEEHardware = cfg.TEEHardware
	hostCfg.MessageHandler = cfg.MessageHandler

	return host.NewHost(&hostCfg)
}

// NewRuntimeWorkerHostFactory creates a new worker host factory for the given runtime.
func (rw *RuntimeHostWorker) NewRuntimeWorkerHostFactory(role node.RolesMask, id signature.PublicKey) (h host.Factory, err error) {
	cfg := rw.commonWorker.GetConfig().RuntimeHost
	rtCfg, ok := cfg.Runtimes[id.ToMapKey()]
	if !ok {
		return nil, fmt.Errorf("runtime host: unknown runtime: %s", id)
	}

	cfgTemplate := host.Config{
		Role:          role,
		ID:            rtCfg.ID,
		WorkerBinary:  cfg.Loader,
		RuntimeBinary: rtCfg.Binary,
		IAS:           rw.commonWorker.IAS,
	}

	switch strings.ToLower(cfg.Backend) {
	case host.BackendUnconfined:
		cfgTemplate.NoSandbox = true
		fallthrough
	case host.BackendSandboxed:
		h = &runtimeWorkerHostSandboxedFactory{cfgTemplate}
	case host.BackendMock:
		h = &runtimeWorkerHostMockFactory{}
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

// RuntimeHostNode provides methods for committee nodes that need to host runtimes.
type RuntimeHostNode struct {
	commonNode *committee.Node

	workerHostFactory host.Factory
	workerHost        host.Host
}

// InitializeRuntimeWorkerHost initializes the runtime worker host for this
// given runtime.
//
// This method must only be called once a runtime has been configured by
// the common committee node -- otherwise the method will panic.
func (n *RuntimeHostNode) InitializeRuntimeWorkerHost() error {
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	if n.commonNode.Runtime == nil {
		panic("runtime host node: initialize runtime worker host without runtime descriptor")
	}

	cfg := host.Config{
		TEEHardware: n.commonNode.Runtime.TEEHardware,
		MessageHandler: NewRuntimeHostHandler(
			n.commonNode.Runtime,
			n.commonNode.Storage,
			n.commonNode.KeyManager,
			n.commonNode.KeyManagerClient,
			n.commonNode.LocalStorage,
		),
	}
	workerHost, err := n.workerHostFactory.NewWorkerHost(cfg)
	if err != nil {
		return err
	}
	if err := workerHost.Start(); err != nil {
		return err
	}
	n.workerHost = workerHost
	return nil
}

// StopRuntimeWorkerHost signals the worker host to stop and waits for it
// to fully stop.
func (n *RuntimeHostNode) StopRuntimeWorkerHost() {
	workerHost := n.GetWorkerHost()
	if workerHost == nil {
		return
	}

	workerHost.Stop()
	<-workerHost.Quit()

	n.commonNode.CrossNode.Lock()
	n.workerHost = nil
	n.commonNode.CrossNode.Unlock()
}

// GetWorkerHost returns the worker host instance used by this committee node.
func (n *RuntimeHostNode) GetWorkerHost() host.Host {
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	return n.workerHost
}

// GetWorkerHostLocked is the same as GetWorkerHost but the caller must ensure
// that the commonNode.CrossNode lock is held while called.
func (n *RuntimeHostNode) GetWorkerHostLocked() host.Host {
	return n.workerHost
}

// NewRuntimeHostNode creates a new runtime host node.
func NewRuntimeHostNode(commonNode *committee.Node, workerHostFactory host.Factory) *RuntimeHostNode {
	return &RuntimeHostNode{
		commonNode:        commonNode,
		workerHostFactory: workerHostFactory,
	}
}
