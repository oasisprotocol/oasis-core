package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanagerApi "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	keymanagerClientApi "github.com/oasisprotocol/oasis-core/go/keymanager/client/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// RuntimeHostNode provides methods for nodes that need to host runtimes.
type RuntimeHostNode struct {
	sync.Mutex

	factory  RuntimeHostHandlerFactory
	notifier protocol.Notifier

	runtime       host.RichRuntime
	runtimeNotify chan struct{}
}

// ProvisionHostedRuntime provisions the configured runtime.
//
// This method may return before the runtime is fully provisioned. The returned runtime will not be
// started automatically, you must call Start explicitly.
func (n *RuntimeHostNode) ProvisionHostedRuntime(ctx context.Context) (host.RichRuntime, protocol.Notifier, error) {
	cfg, provisioner, err := n.factory.GetRuntime().Host(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get runtime host: %w", err)
	}
	cfg.MessageHandler = n.factory.NewRuntimeHostHandler()

	// Provision the runtime.
	prt, err := provisioner.NewRuntime(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to provision runtime: %w", err)
	}
	notifier := n.factory.NewRuntimeHostNotifier(ctx, prt)
	rr := host.NewRichRuntime(prt)

	n.Lock()
	n.runtime = rr
	n.notifier = notifier
	n.Unlock()

	close(n.runtimeNotify)

	return rr, notifier, nil
}

// GetHostedRuntime returns the provisioned hosted runtime (if any).
func (n *RuntimeHostNode) GetHostedRuntime() host.RichRuntime {
	n.Lock()
	rt := n.runtime
	n.Unlock()
	return rt
}

// WaitHostedRuntime waits for the hosted runtime to be provisioned and returns it.
func (n *RuntimeHostNode) WaitHostedRuntime(ctx context.Context) (host.RichRuntime, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.runtimeNotify:
	}

	return n.GetHostedRuntime(), nil
}

// RuntimeHostHandlerFactory is an interface that can be used to create new runtime handlers and
// notifiers when provisioning hosted runtimes.
type RuntimeHostHandlerFactory interface {
	// GetRuntime returns the registered runtime for which a runtime host handler is to be created.
	GetRuntime() Runtime

	// NewRuntimeHostHandler creates a new runtime host handler.
	NewRuntimeHostHandler() protocol.Handler

	// NewRuntimeHostNotifier creates a new runtime host notifier.
	NewRuntimeHostNotifier(ctx context.Context, host host.Runtime) protocol.Notifier
}

// NewRuntimeHostNode creates a new runtime host node.
func NewRuntimeHostNode(factory RuntimeHostHandlerFactory) (*RuntimeHostNode, error) {
	return &RuntimeHostNode{
		factory:       factory,
		runtimeNotify: make(chan struct{}),
	}, nil
}

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("endpoint not supported")
)

// RuntimeHostHandlerEnvironment is the host environment interface.
type RuntimeHostHandlerEnvironment interface {
	// GetCurrentBlock returns the most recent runtime block.
	GetCurrentBlock(ctx context.Context) (*block.Block, error)

	// GetKeyManagerClient returns the key manager client for this runtime.
	GetKeyManagerClient(ctx context.Context) (keymanagerClientApi.Client, error)
}

// RuntimeHostHandler is a runtime host handler suitable for compute runtimes. It provides the
// required set of methods for interacting with the outside world.
type runtimeHostHandler struct {
	env       RuntimeHostHandlerEnvironment
	runtime   Runtime
	consensus consensus.Backend
}

// Implements protocol.Handler.
func (h *runtimeHostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	// RPC.
	if body.HostRPCCallRequest != nil {
		switch body.HostRPCCallRequest.Endpoint {
		case keymanagerApi.EnclaveRPCEndpoint:
			// Call into the remote key manager.
			kmCli, err := h.env.GetKeyManagerClient(ctx)
			if err != nil {
				return nil, err
			}
			res, err := kmCli.CallRemote(ctx, body.HostRPCCallRequest.Request)
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
			rs = h.runtime.Storage()

			// Prioritize nodes that signed the last storage receipts.
			if blk, _ := h.env.GetCurrentBlock(ctx); blk != nil {
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
		value, err := h.runtime.LocalStorage().Get(body.HostLocalStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageGetResponse: &protocol.HostLocalStorageGetResponse{Value: value}}, nil
	}
	if body.HostLocalStorageSetRequest != nil {
		if err := h.runtime.LocalStorage().Set(body.HostLocalStorageSetRequest.Key, body.HostLocalStorageSetRequest.Value); err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageSetResponse: &protocol.Empty{}}, nil
	}

	return nil, errMethodNotSupported
}

// runtimeHostNotifier is a runtime host notifier suitable for compute runtimes. It handles things
// like key manager policy updates.
type runtimeHostNotifier struct {
	sync.Mutex

	ctx context.Context

	stopCh chan struct{}

	started   bool
	runtime   Runtime
	host      host.Runtime
	consensus consensus.Backend

	logger *logging.Logger
}

func (n *runtimeHostNotifier) watchPolicyUpdates() {
	// Subscribe to runtime descriptor updates.
	dscCh, dscSub, err := n.runtime.WatchRegistryDescriptor()
	if err != nil {
		n.logger.Error("failed to subscribe to registry descriptor updates",
			"err", err,
		)
		return
	}
	defer dscSub.Close()

	// Subscribe to key manager status updates.
	stCh, stSub := n.consensus.KeyManager().WatchStatuses()
	defer stSub.Close()
	n.logger.Debug("watching policy updates")

	var rtDsc *registry.Runtime
	for {
		var st *keymanagerApi.Status
		select {
		case <-n.ctx.Done():
			n.logger.Debug("context canceled")
			return
		case <-n.stopCh:
			n.logger.Debug("termination requested")
			return
		case rtDsc = <-dscCh:
			n.logger.Debug("got registry descriptor update")

			// Ignore updates if key manager is not needed.
			if rtDsc.KeyManager == nil {
				n.logger.Debug("no key manager needed for this runtime")
				continue
			}
			// GetStatus(context.Context, *registry.NamespaceQuery) (*Status, error)

			var err error
			st, err = n.consensus.KeyManager().GetStatus(n.ctx, &registry.NamespaceQuery{
				Height: consensus.HeightLatest,
				ID:     *rtDsc.KeyManager,
			})
			if err != nil {
				n.logger.Warn("failed to fetch key manager status",
					"err", err,
				)
				continue
			}
		case st = <-stCh:
			// Ignore status updates if key manager is not yet known (is nil)
			// or if the status update is for a different key manager.
			if rtDsc == nil || !st.ID.Equal(rtDsc.KeyManager) {
				continue
			}
		}

		// Update key manager policy.
		n.logger.Debug("got policy update", "status", st)

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

// Implements protocol.Notifier.
func (n *runtimeHostNotifier) Start() error {
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
func (n *runtimeHostNotifier) Stop() {
	close(n.stopCh)
}

// NewRuntimeHostNotifier returns a protocol notifier that handles key manager policy updates.
func NewRuntimeHostNotifier(
	ctx context.Context,
	runtime Runtime,
	host host.Runtime,
	consensus consensus.Backend,
) protocol.Notifier {
	return &runtimeHostNotifier{
		ctx:       ctx,
		stopCh:    make(chan struct{}),
		runtime:   runtime,
		host:      host,
		consensus: consensus,
		logger:    logging.GetLogger("runtime/registry/host"),
	}
}

// NewRuntimeHostHandler returns a protocol handler that provides the required host methods for the
// runtime to interact with the outside world.
//
// The passed identity may be nil.
func NewRuntimeHostHandler(
	env RuntimeHostHandlerEnvironment,
	runtime Runtime,
	consensus consensus.Backend,
) protocol.Handler {
	return &runtimeHostHandler{
		env:       env,
		runtime:   runtime,
		consensus: consensus,
	}
}
