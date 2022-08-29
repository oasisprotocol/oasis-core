package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	consensusResults "github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/results"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/multi"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// notifyTimeout is the maximum time to wait for a notification to be processed by the runtime.
const notifyTimeout = 10 * time.Second

// RuntimeHostNode provides methods for nodes that need to host runtimes.
type RuntimeHostNode struct {
	sync.Mutex

	factory  RuntimeHostHandlerFactory
	notifier protocol.Notifier

	agg           *multi.Aggregate
	runtime       host.RichRuntime
	runtimeNotify chan struct{}
}

// ProvisionHostedRuntime provisions the configured runtime.
//
// This method may return before the runtime is fully provisioned. The returned runtime will not be
// started automatically, you must call Start explicitly.
func (n *RuntimeHostNode) ProvisionHostedRuntime(ctx context.Context) (host.RichRuntime, protocol.Notifier, error) {
	runtime := n.factory.GetRuntime()
	cfgs, provisioner, err := runtime.Host(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get runtime host: %w", err)
	}

	// Provision the handler that implements the host RHP methods.
	msgHandler := n.factory.NewRuntimeHostHandler()

	rts := make(map[version.Version]host.Runtime)
	for version, cfg := range cfgs {
		rtCfg := *cfg
		rtCfg.MessageHandler = msgHandler

		// Provision the runtime.
		if rts[version], err = provisioner.NewRuntime(ctx, rtCfg); err != nil {
			return nil, nil, fmt.Errorf("failed to provision runtime version %s: %w", version, err)
		}
	}

	agg, err := multi.New(ctx, runtime.ID(), rts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to provision aggregate runtime: %w", err)
	}

	notifier := n.factory.NewRuntimeHostNotifier(ctx, agg)
	rr := host.NewRichRuntime(agg)

	n.Lock()
	n.agg = agg.(*multi.Aggregate)
	n.runtime = rr
	n.notifier = notifier
	n.Unlock()

	close(n.runtimeNotify)

	return rr, notifier, nil
}

// GetHostedRuntime returns the provisioned hosted runtime (if any).
func (n *RuntimeHostNode) GetHostedRuntime() host.RichRuntime {
	n.Lock()
	defer n.Unlock()

	return n.runtime
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

// SetHostedRuntimeVersion sets the currently active version for the hosted runtime.
func (n *RuntimeHostNode) SetHostedRuntimeVersion(ctx context.Context, version version.Version) error {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return fmt.Errorf("runtime not available")
	}

	return agg.SetVersion(ctx, version)
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
	GetKeyManagerClient(ctx context.Context) (runtimeKeymanager.Client, error)

	// GetTxPool returns the transaction pool for this runtime.
	GetTxPool(ctx context.Context) (txpool.TransactionPool, error)
}

// RuntimeHostHandler is a runtime host handler suitable for compute runtimes. It provides the
// required set of methods for interacting with the outside world.
type runtimeHostHandler struct {
	env       RuntimeHostHandlerEnvironment
	runtime   Runtime
	consensus consensus.Backend
}

func (h *runtimeHostHandler) handleHostRPCCall(
	ctx context.Context,
	request *protocol.HostRPCCallRequest,
) (*protocol.Body, error) {
	switch request.Endpoint {
	case runtimeKeymanager.EnclaveRPCEndpoint:
		// Call into the remote key manager.
		kmCli, err := h.env.GetKeyManagerClient(ctx)
		if err != nil {
			return nil, err
		}
		res, err := kmCli.CallEnclave(ctx, request.Request, request.PeerFeedback)
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

func (h *runtimeHostHandler) handleHostStorageSync(
	ctx context.Context,
	request *protocol.HostStorageSyncRequest,
) (*protocol.Body, error) {
	var rs syncer.ReadSyncer
	switch request.Endpoint {
	case protocol.HostStorageEndpointRuntime:
		// Runtime storage.
		rs = h.runtime.Storage()
	case protocol.HostStorageEndpointConsensus:
		// Consensus state storage.
		rs = h.consensus.State()
	default:
		return nil, errEndpointNotSupported
	}

	var rsp *storage.ProofResponse
	var err error
	switch {
	case request.SyncGet != nil:
		rsp, err = rs.SyncGet(ctx, request.SyncGet)
	case request.SyncGetPrefixes != nil:
		rsp, err = rs.SyncGetPrefixes(ctx, request.SyncGetPrefixes)
	case request.SyncIterate != nil:
		rsp, err = rs.SyncIterate(ctx, request.SyncIterate)
	default:
		return nil, errMethodNotSupported
	}
	if err != nil {
		return nil, err
	}

	return &protocol.Body{HostStorageSyncResponse: &protocol.HostStorageSyncResponse{ProofResponse: rsp}}, nil
}

func (h *runtimeHostHandler) handleHostLocalStorage(
	ctx context.Context,
	body *protocol.Body,
) (*protocol.Body, error) {
	switch {
	case body.HostLocalStorageGetRequest != nil:
		value, err := h.runtime.LocalStorage().Get(body.HostLocalStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageGetResponse: &protocol.HostLocalStorageGetResponse{Value: value}}, nil
	case body.HostLocalStorageSetRequest != nil:
		if err := h.runtime.LocalStorage().Set(body.HostLocalStorageSetRequest.Key, body.HostLocalStorageSetRequest.Value); err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageSetResponse: &protocol.Empty{}}, nil
	default:
		return nil, errMethodNotSupported
	}
}

func (h *runtimeHostHandler) handleHostFetchConsensusBlock(
	ctx context.Context,
	request *protocol.HostFetchConsensusBlockRequest,
) (*protocol.Body, error) {
	lb, err := h.consensus.GetLightBlock(ctx, int64(request.Height))
	if err != nil {
		return nil, err
	}
	return &protocol.Body{HostFetchConsensusBlockResponse: &protocol.HostFetchConsensusBlockResponse{
		Block: *lb,
	}}, nil
}

func (h *runtimeHostHandler) handleHostFetchConsensusEvents(
	ctx context.Context,
	request *protocol.HostFetchConsensusEventsRequest,
) (*protocol.Body, error) {
	var evs []*consensusResults.Event
	switch request.Kind {
	case protocol.EventKindStaking:
		sevs, err := h.consensus.Staking().GetEvents(ctx, int64(request.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(sevs))
		for _, sev := range sevs {
			evs = append(evs, &consensusResults.Event{Staking: sev})
		}
	case protocol.EventKindRegistry:
		revs, err := h.consensus.Registry().GetEvents(ctx, int64(request.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(revs))
		for _, rev := range revs {
			evs = append(evs, &consensusResults.Event{Registry: rev})
		}
	case protocol.EventKindRootHash:
		revs, err := h.consensus.RootHash().GetEvents(ctx, int64(request.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(revs))
		for _, rev := range revs {
			evs = append(evs, &consensusResults.Event{RootHash: rev})
		}
	case protocol.EventKindGovernance:
		gevs, err := h.consensus.Governance().GetEvents(ctx, int64(request.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(gevs))
		for _, gev := range gevs {
			evs = append(evs, &consensusResults.Event{Governance: gev})
		}
	default:
		return nil, errMethodNotSupported
	}
	return &protocol.Body{HostFetchConsensusEventsResponse: &protocol.HostFetchConsensusEventsResponse{
		Events: evs,
	}}, nil
}

func (h *runtimeHostHandler) handleHostFetchGenesisHeight(
	ctx context.Context,
	request *protocol.HostFetchGenesisHeightRequest,
) (*protocol.Body, error) {
	doc, err := h.consensus.GetGenesisDocument(ctx)
	if err != nil {
		return nil, err
	}
	return &protocol.Body{HostFetchGenesisHeightResponse: &protocol.HostFetchGenesisHeightResponse{
		Height: uint64(doc.Height),
	}}, nil
}

func (h *runtimeHostHandler) handleHostFetchTxBatch(
	ctx context.Context,
	request *protocol.HostFetchTxBatchRequest,
) (*protocol.Body, error) {
	txPool, err := h.env.GetTxPool(ctx)
	if err != nil {
		return nil, err
	}

	batch := txPool.GetSchedulingExtra(request.Offset, request.Limit)
	raw := make([][]byte, 0, len(batch))
	for _, tx := range batch {
		raw = append(raw, tx.Raw())
	}

	return &protocol.Body{HostFetchTxBatchResponse: &protocol.HostFetchTxBatchResponse{
		Batch: raw,
	}}, nil
}

// Implements protocol.Handler.
func (h *runtimeHostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	switch {
	case body.HostRPCCallRequest != nil:
		// RPC.
		return h.handleHostRPCCall(ctx, body.HostRPCCallRequest)
	case body.HostStorageSyncRequest != nil:
		// Storage.
		return h.handleHostStorageSync(ctx, body.HostStorageSyncRequest)
	case body.HostLocalStorageGetRequest != nil, body.HostLocalStorageSetRequest != nil:
		// Local storage.
		return h.handleHostLocalStorage(ctx, body)
	case body.HostFetchConsensusBlockRequest != nil:
		// Consensus light client.
		return h.handleHostFetchConsensusBlock(ctx, body.HostFetchConsensusBlockRequest)
	case body.HostFetchConsensusEventsRequest != nil:
		// Consensus events.
		return h.handleHostFetchConsensusEvents(ctx, body.HostFetchConsensusEventsRequest)
	case body.HostFetchGenesisHeightRequest != nil:
		// Consensus genesis height.
		return h.handleHostFetchGenesisHeight(ctx, body.HostFetchGenesisHeightRequest)
	case body.HostFetchTxBatchRequest != nil:
		// Transaction pool.
		return h.handleHostFetchTxBatch(ctx, body.HostFetchTxBatchRequest)
	default:
		return nil, errMethodNotSupported
	}
}

// runtimeHostNotifier is a runtime host notifier suitable for compute runtimes. It handles things
// like key manager policy updates.
type runtimeHostNotifier struct {
	sync.Mutex

	ctx context.Context

	stopCh chan struct{}

	started   bool
	runtime   Runtime
	host      host.RichRuntime
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

	// Subscribe to runtime host events.
	evCh, evSub, err := n.host.WatchEvents(n.ctx)
	if err != nil {
		n.logger.Error("failed to subscribe to runtime host events",
			"err", err,
		)
		return
	}
	defer evSub.Close()

	var (
		rtDsc *registry.Runtime
		st    *keymanager.Status
	)
	for {
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
		case ev := <-evCh:
			// Runtime host changes, make sure to update the policy if runtime is restarted.
			if ev.Started == nil && ev.Updated == nil {
				continue
			}
		}

		// Make sure that we actually have a policy.
		if st == nil {
			continue
		}

		// Update key manager policy.
		n.logger.Debug("got policy update", "status", st)

		raw := cbor.Marshal(st.Policy)
		req := &protocol.Body{RuntimeKeyManagerPolicyUpdateRequest: &protocol.RuntimeKeyManagerPolicyUpdateRequest{
			SignedPolicyRaw: raw,
		}}

		ctx, cancel := context.WithTimeout(n.ctx, notifyTimeout)
		response, err := n.host.Call(ctx, req)
		cancel()
		if err != nil {
			n.logger.Error("failed dispatching key manager policy update to runtime",
				"err", err,
			)
			continue
		}
		n.logger.Debug("key manager policy updated dispatched", "response", response)
	}
}

func (n *runtimeHostNotifier) watchConsensusLightBlocks() {
	rawCh, sub, err := n.consensus.WatchBlocks(n.ctx)
	if err != nil {
		n.logger.Error("failed to subscribe to consensus block updates",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Create a ring channel with a capacity of one as we only care about the latest block.
	blkCh := channels.NewRingChannel(channels.BufferCap(1))
	go func() {
		for blk := range rawCh {
			blkCh.In() <- blk
		}
		blkCh.Close()
	}()

	n.logger.Debug("watching consensus layer blocks")

	for {
		select {
		case <-n.ctx.Done():
			n.logger.Debug("context canceled")
			return
		case <-n.stopCh:
			n.logger.Debug("termination requested")
			return
		case rawBlk, ok := <-blkCh.Out():
			if !ok {
				return
			}
			blk := rawBlk.(*consensus.Block)

			// Notify the runtime that a new consensus layer block is available.
			ctx, cancel := context.WithTimeout(n.ctx, notifyTimeout)
			err = n.host.ConsensusSync(ctx, uint64(blk.Height))
			cancel()
			if err != nil {
				n.logger.Error("failed to notify runtime of a new consensus layer block",
					"err", err,
					"height", blk.Height,
				)
				continue
			}
			n.logger.Debug("runtime notified of new consensus layer block",
				"height", blk.Height,
			)
		}
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
	go n.watchConsensusLightBlocks()

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
	hostRt host.Runtime,
	consensus consensus.Backend,
) protocol.Notifier {
	return &runtimeHostNotifier{
		ctx:       ctx,
		stopCh:    make(chan struct{}),
		runtime:   runtime,
		host:      host.NewRichRuntime(hostRt),
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
