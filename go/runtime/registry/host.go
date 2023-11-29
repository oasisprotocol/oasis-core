package registry

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/eapache/channels"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusResults "github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/results"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/multi"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// notifyTimeout is the maximum time to wait for a notification to be processed by the runtime.
	notifyTimeout = 10 * time.Second

	// retryInterval is the time interval used between failed key manager updates.
	retryInterval = time.Second

	// minAttestationInterval is the minimum attestation interval.
	minAttestationInterval = 5 * time.Minute
)

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

	// Ensure registry descriptor is ready as it is required for obtaining Host configuration.
	_, err := runtime.RegistryDescriptor(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wait for registry descriptor: %w", err)
	}
	cfgs, provisioner, err := runtime.Host()
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
		if rts[version], err = provisioner.NewRuntime(rtCfg); err != nil {
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

// GetHostedRuntimeCapabilityTEE returns the CapabilityTEE for a specific runtime version.
func (n *RuntimeHostNode) GetHostedRuntimeCapabilityTEE(version version.Version) (*node.CapabilityTEE, error) {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return nil, fmt.Errorf("runtime not available")
	}

	rt, err := agg.GetVersion(version)
	if err != nil {
		return nil, err
	}
	return rt.GetCapabilityTEE()
}

// SetHostedRuntimeVersion sets the currently active and next versions for the hosted runtime.
func (n *RuntimeHostNode) SetHostedRuntimeVersion(active version.Version, next *version.Version) error {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return fmt.Errorf("runtime not available")
	}

	return agg.SetVersion(active, next)
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
	// GetKeyManagerClient returns the key manager client for this runtime.
	GetKeyManagerClient() (runtimeKeymanager.Client, error)

	// GetTxPool returns the transaction pool for this runtime.
	GetTxPool() (txpool.TransactionPool, error)

	// GetNodeIdentity returns the identity of a node running this runtime.
	GetNodeIdentity() (*identity.Identity, error)

	// GetLightClient returns the consensus light client.
	GetLightClient() (consensus.LightClient, error)
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
	rq *protocol.HostRPCCallRequest,
) (*protocol.HostRPCCallResponse, error) {
	switch rq.Endpoint {
	case runtimeKeymanager.EnclaveRPCEndpoint:
		// Call into the remote key manager.
		kmCli, err := h.env.GetKeyManagerClient()
		if err != nil {
			return nil, err
		}
		res, node, err := kmCli.CallEnclave(ctx, rq.Request, rq.Nodes, rq.Kind, rq.PeerFeedback)
		if err != nil {
			return nil, err
		}
		// Don't send node identity if the runtime doesn't support explicit key manager RPC calls.
		if rq.Nodes == nil {
			return &protocol.HostRPCCallResponse{
				Response: res,
			}, nil
		}
		return &protocol.HostRPCCallResponse{
			Response: res,
			Node:     &node,
		}, nil
	default:
		return nil, errEndpointNotSupported
	}
}

func (h *runtimeHostHandler) handleHostStorageSync(
	ctx context.Context,
	rq *protocol.HostStorageSyncRequest,
) (*protocol.HostStorageSyncResponse, error) {
	var rs syncer.ReadSyncer
	switch rq.Endpoint {
	case protocol.HostStorageEndpointRuntime:
		// Runtime storage.
		rs = h.runtime.Storage()
		if rs == nil {
			// May be unsupported for unmanaged runtimes like the key manager.
			return nil, errEndpointNotSupported
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

	return &protocol.HostStorageSyncResponse{ProofResponse: rsp}, nil
}

func (h *runtimeHostHandler) handleHostLocalStorageGet(
	rq *protocol.HostLocalStorageGetRequest,
) (*protocol.HostLocalStorageGetResponse, error) {
	value, err := h.runtime.LocalStorage().Get(rq.Key)
	if err != nil {
		return nil, err
	}
	return &protocol.HostLocalStorageGetResponse{Value: value}, nil
}

func (h *runtimeHostHandler) handleHostLocalStorageSet(
	rq *protocol.HostLocalStorageSetRequest,
) (*protocol.Empty, error) {
	if err := h.runtime.LocalStorage().Set(rq.Key, rq.Value); err != nil {
		return nil, err
	}
	return &protocol.Empty{}, nil
}

func (h *runtimeHostHandler) handleHostFetchConsensusBlock(
	ctx context.Context,
	rq *protocol.HostFetchConsensusBlockRequest,
) (*protocol.HostFetchConsensusBlockResponse, error) {
	// Invoke the light client. If a local full node is available the light
	// client will internally query the local node first.
	lc, err := h.env.GetLightClient()
	if err != nil {
		return nil, err
	}
	blk, _, err := lc.GetLightBlock(ctx, int64(rq.Height))
	if err != nil {
		return nil, fmt.Errorf("light block fetch failure: %w", err)
	}

	return &protocol.HostFetchConsensusBlockResponse{Block: *blk}, nil
}

func (h *runtimeHostHandler) handleHostFetchConsensusEvents(
	ctx context.Context,
	rq *protocol.HostFetchConsensusEventsRequest,
) (*protocol.HostFetchConsensusEventsResponse, error) {
	var evs []*consensusResults.Event
	switch rq.Kind {
	case protocol.EventKindStaking:
		sevs, err := h.consensus.Staking().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(sevs))
		for _, sev := range sevs {
			evs = append(evs, &consensusResults.Event{Staking: sev})
		}
	case protocol.EventKindRegistry:
		revs, err := h.consensus.Registry().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(revs))
		for _, rev := range revs {
			evs = append(evs, &consensusResults.Event{Registry: rev})
		}
	case protocol.EventKindRootHash:
		revs, err := h.consensus.RootHash().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(revs))
		for _, rev := range revs {
			evs = append(evs, &consensusResults.Event{RootHash: rev})
		}
	case protocol.EventKindGovernance:
		gevs, err := h.consensus.Governance().GetEvents(ctx, int64(rq.Height))
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
	return &protocol.HostFetchConsensusEventsResponse{Events: evs}, nil
}

func (h *runtimeHostHandler) handleHostFetchGenesisHeight(
	ctx context.Context,
) (*protocol.HostFetchGenesisHeightResponse, error) {
	doc, err := h.consensus.GetGenesisDocument(ctx)
	if err != nil {
		return nil, err
	}
	return &protocol.HostFetchGenesisHeightResponse{Height: uint64(doc.Height)}, nil
}

func (h *runtimeHostHandler) handleHostFetchTxBatch(
	rq *protocol.HostFetchTxBatchRequest,
) (*protocol.HostFetchTxBatchResponse, error) {
	txPool, err := h.env.GetTxPool()
	if err != nil {
		return nil, err
	}

	batch := txPool.GetSchedulingExtra(rq.Offset, rq.Limit)
	raw := make([][]byte, 0, len(batch))
	for _, tx := range batch {
		raw = append(raw, tx.Raw())
	}

	return &protocol.HostFetchTxBatchResponse{Batch: raw}, nil
}

func (h *runtimeHostHandler) handleHostFetchBlockMetadataTx(
	ctx context.Context,
	rq *protocol.HostFetchBlockMetadataTxRequest,
) (*protocol.HostFetchBlockMetadataTxResponse, error) {
	tps, err := h.consensus.GetTransactionsWithProofs(ctx, int64(rq.Height))
	if err != nil {
		return nil, err
	}

	// The block metadata transaction should be located at the end of the block.
	for i := len(tps.Transactions) - 1; i >= 0; i-- {
		rawTx := tps.Transactions[i]

		var sigTx transaction.SignedTransaction
		if err = cbor.Unmarshal(rawTx, &sigTx); err != nil {
			continue
		}

		// Signature already verified by the validators, skipping.

		var tx transaction.Transaction
		if err = cbor.Unmarshal(sigTx.Blob, &tx); err != nil {
			continue
		}

		if tx.Method != consensus.MethodMeta {
			continue
		}

		return &protocol.HostFetchBlockMetadataTxResponse{
			SignedTx: &sigTx,
			Proof: &transaction.Proof{
				Height:   int64(rq.Height),
				RawProof: tps.Proofs[i],
			},
		}, nil
	}

	return nil, fmt.Errorf("block metadata transaction not found")
}

func (h *runtimeHostHandler) handleHostProveFreshness(
	ctx context.Context,
	rq *protocol.HostProveFreshnessRequest,
) (*protocol.HostProveFreshnessResponse, error) {
	identity, err := h.env.GetNodeIdentity()
	if err != nil {
		return nil, err
	}
	tx := registry.NewProveFreshnessTx(0, nil, rq.Blob)
	sigTx, proof, err := consensus.SignAndSubmitTxWithProof(ctx, h.consensus, identity.NodeSigner, tx)
	if err != nil {
		return nil, err
	}

	return &protocol.HostProveFreshnessResponse{
		SignedTx: sigTx,
		Proof:    proof,
	}, nil
}

func (h *runtimeHostHandler) handleHostIdentity() (*protocol.HostIdentityResponse, error) {
	identity, err := h.env.GetNodeIdentity()
	if err != nil {
		return nil, err
	}

	return &protocol.HostIdentityResponse{
		NodeID: identity.NodeSigner.Public(),
	}, nil
}

// Implements protocol.Handler.
func (h *runtimeHostHandler) Handle(ctx context.Context, rq *protocol.Body) (*protocol.Body, error) {
	var (
		rsp protocol.Body
		err error
	)

	switch {
	case rq.HostRPCCallRequest != nil:
		// RPC.
		rsp.HostRPCCallResponse, err = h.handleHostRPCCall(ctx, rq.HostRPCCallRequest)
	case rq.HostStorageSyncRequest != nil:
		// Storage sync.
		rsp.HostStorageSyncResponse, err = h.handleHostStorageSync(ctx, rq.HostStorageSyncRequest)
	case rq.HostLocalStorageGetRequest != nil:
		// Local storage get.
		rsp.HostLocalStorageGetResponse, err = h.handleHostLocalStorageGet(rq.HostLocalStorageGetRequest)
	case rq.HostLocalStorageSetRequest != nil:
		// Local storage set.
		rsp.HostLocalStorageSetResponse, err = h.handleHostLocalStorageSet(rq.HostLocalStorageSetRequest)
	case rq.HostFetchConsensusBlockRequest != nil:
		// Consensus light client.
		rsp.HostFetchConsensusBlockResponse, err = h.handleHostFetchConsensusBlock(ctx, rq.HostFetchConsensusBlockRequest)
	case rq.HostFetchConsensusEventsRequest != nil:
		// Consensus events.
		rsp.HostFetchConsensusEventsResponse, err = h.handleHostFetchConsensusEvents(ctx, rq.HostFetchConsensusEventsRequest)
	case rq.HostFetchGenesisHeightRequest != nil:
		// Consensus genesis height.
		rsp.HostFetchGenesisHeightResponse, err = h.handleHostFetchGenesisHeight(ctx)
	case rq.HostFetchTxBatchRequest != nil:
		// Transaction pool.
		rsp.HostFetchTxBatchResponse, err = h.handleHostFetchTxBatch(rq.HostFetchTxBatchRequest)
	case rq.HostFetchBlockMetadataTxRequest != nil:
		// Block metadata.
		rsp.HostFetchBlockMetadataTxResponse, err = h.handleHostFetchBlockMetadataTx(ctx, rq.HostFetchBlockMetadataTxRequest)
	case rq.HostProveFreshnessRequest != nil:
		// Prove freshness.
		rsp.HostProveFreshnessResponse, err = h.handleHostProveFreshness(ctx, rq.HostProveFreshnessRequest)
	case rq.HostIdentityRequest != nil:
		// Host identity.
		rsp.HostIdentityResponse, err = h.handleHostIdentity()
	default:
		err = errMethodNotSupported
	}

	if err != nil {
		return nil, err
	}
	return &rsp, nil
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

	var (
		kmRtID *common.Namespace
		done   bool
	)

	for !done {
		done = func() bool {
			// Start watching key manager policy updates.
			var wg sync.WaitGroup
			defer wg.Wait()

			ctx, cancel := context.WithCancel(n.ctx)
			defer cancel()

			wg.Add(1)
			go func(kmRtID *common.Namespace) {
				defer wg.Done()
				n.watchKmPolicyUpdates(ctx, kmRtID)
			}(kmRtID)

			// Restart the updater if the runtime changes the key manager. This should happen
			// at most once as runtimes are not allowed to change the manager once set.
			for {
				select {
				case <-n.ctx.Done():
					n.logger.Debug("context canceled")
					return true
				case <-n.stopCh:
					n.logger.Debug("termination requested")
					return true
				case rtDsc := <-dscCh:
					n.logger.Debug("got registry descriptor update")

					if rtDsc.Kind != registry.KindCompute {
						return true
					}

					if kmRtID.Equal(rtDsc.KeyManager) {
						break
					}

					kmRtID = rtDsc.KeyManager
					return false
				}
			}
		}()
	}
}

func (n *runtimeHostNotifier) watchKmPolicyUpdates(ctx context.Context, kmRtID *common.Namespace) {
	// No need to watch anything if key manager is not set.
	if kmRtID == nil {
		return
	}

	n.logger.Debug("watching key manager policy updates", "keymanager", kmRtID)

	// Subscribe to key manager status updates (policy might change).
	stCh, stSub := n.consensus.KeyManager().WatchStatuses()
	defer stSub.Close()

	// Subscribe to epoch transitions (quote policy might change).
	epoCh, sub, err := n.consensus.Beacon().WatchEpochs(ctx)
	if err != nil {
		n.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Subscribe to runtime host events (policies will be lost on restarts).
	evCh, evSub, err := n.host.WatchEvents(n.ctx)
	if err != nil {
		n.logger.Error("failed to subscribe to runtime host events",
			"err", err,
		)
		return
	}
	defer evSub.Close()

	retryTicker := time.NewTicker(retryInterval)
	defer retryTicker.Stop()

	var (
		statusUpdated      = true
		quotePolicyUpdated = true
		runtimeInfoUpdated = false
	)

	var (
		st *keymanager.Status
		sc *node.SGXConstraints
		vi *registry.VersionInfo
		ri *protocol.RuntimeInfoResponse
	)

	for {
		// Fetch runtime info so that we know which features the current runtime version supports.
		if !runtimeInfoUpdated {
			if ri, err = n.host.GetInfo(ctx); err != nil {
				n.logger.Error("failed to fetch runtime info",
					"err", err,
				)
				return
			}
			runtimeInfoUpdated = true
		}

		// Make sure that we actually have a new status.
		if !statusUpdated && st != nil {
			switch {
			case ri.Features.KeyManagerStatusUpdates:
				if err = n.updateKeyManagerStatus(ctx, st); err == nil {
					statusUpdated = true
				}
			case st.Policy != nil:
				if err = n.updateKeyManagerPolicy(ctx, st.Policy); err == nil {
					statusUpdated = true
				}
			}
		}

		// Make sure that we actually have a new quote policy and that the current runtime version
		// supports quote policy updates.
		if !quotePolicyUpdated && sc != nil && sc.Policy != nil && ri.Features.KeyManagerQuotePolicyUpdates {
			if err = n.updateKeyManagerQuotePolicy(ctx, sc.Policy); err == nil {
				quotePolicyUpdated = true
			}
		}

		select {
		case <-ctx.Done():
			return
		case newSt := <-stCh:
			// Ignore status updates for a different key manager.
			if !newSt.ID.Equal(kmRtID) {
				continue
			}
			st = newSt

			statusUpdated = false
		case epoch := <-epoCh:
			// Check if the key manager was redeployed, as that is when a new quote policy might
			// take effect.
			dsc, err := n.consensus.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{
				Height: consensus.HeightLatest,
				ID:     *kmRtID,
			})
			if err != nil {
				n.logger.Error("failed to query key manager runtime descriptor",
					"err", err,
				)
				continue
			}

			// Quote polices can only be set on SGX hardwares.
			if dsc.TEEHardware != node.TEEHardwareIntelSGX {
				continue
			}

			// No need to update the policy if the key manager is sill running the same version.
			newVi := dsc.ActiveDeployment(epoch)
			if newVi.Equal(vi) {
				continue
			}
			vi = newVi

			// Parse SGX constraints.
			var newSc node.SGXConstraints
			if err := cbor.Unmarshal(vi.TEE, &newSc); err != nil {
				n.logger.Error("malformed SGX constraints",
					"err", err,
				)
				continue
			}
			sc = &newSc

			quotePolicyUpdated = false
		case ev := <-evCh:
			// Runtime host changes, make sure to update the policies if runtime is restarted.
			if ev.Started == nil && ev.Updated == nil {
				continue
			}

			statusUpdated = false
			quotePolicyUpdated = false
			runtimeInfoUpdated = false
		case <-retryTicker.C:
			// Retry updates if some of them failed. When using CometBFT as a backend service
			// the host will see the new state one block before the consensus verifier as the former
			// sees the block H after it is executed while the latter needs to trust the block H
			// first by verifying the signatures which are only available after the block H+1
			// finalizes.
		}
	}
}

func (n *runtimeHostNotifier) updateKeyManagerStatus(ctx context.Context, status *keymanager.Status) error {
	n.logger.Debug("got key manager status update", "status", status)

	req := &protocol.Body{RuntimeKeyManagerStatusUpdateRequest: &protocol.RuntimeKeyManagerStatusUpdateRequest{
		Status: *status,
	}}

	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	if _, err := n.host.Call(ctx, req); err != nil {
		n.logger.Error("failed dispatching key manager status update to runtime",
			"err", err,
		)
		return err
	}

	n.logger.Debug("key manager status update dispatched")
	return nil
}

func (n *runtimeHostNotifier) updateKeyManagerPolicy(ctx context.Context, policy *keymanager.SignedPolicySGX) error {
	n.logger.Debug("got key manager policy update", "policy", policy)

	raw := cbor.Marshal(policy)
	req := &protocol.Body{RuntimeKeyManagerPolicyUpdateRequest: &protocol.RuntimeKeyManagerPolicyUpdateRequest{
		SignedPolicyRaw: raw,
	}}

	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	if _, err := n.host.Call(ctx, req); err != nil {
		n.logger.Error("failed dispatching key manager policy update to runtime",
			"err", err,
		)
		return err
	}

	n.logger.Debug("key manager policy update dispatched")
	return nil
}

func (n *runtimeHostNotifier) updateKeyManagerQuotePolicy(ctx context.Context, policy *quote.Policy) error {
	n.logger.Debug("got key manager quote policy update", "policy", policy)

	req := &protocol.Body{RuntimeKeyManagerQuotePolicyUpdateRequest: &protocol.RuntimeKeyManagerQuotePolicyUpdateRequest{
		Policy: *policy,
	}}

	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	if _, err := n.host.Call(ctx, req); err != nil {
		n.logger.Error("failed dispatching key manager quote policy update to runtime",
			"err", err,
		)
		return err
	}
	n.logger.Debug("key manager quote policy update dispatched")
	return nil
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
		defer blkCh.Close()

		for blk := range rawCh {
			blkCh.In() <- blk
		}
	}()

	// Subscribe to runtime descriptor updates.
	dscCh, dscSub, err := n.runtime.WatchRegistryDescriptor()
	if err != nil {
		n.logger.Error("failed to subscribe to registry descriptor updates",
			"err", err,
		)
		return
	}
	defer dscSub.Close()

	n.logger.Debug("watching consensus layer blocks")

	var (
		maxAttestationAge           uint64
		lastAttestationUpdateHeight uint64
		lastAttestationUpdate       time.Time
	)
	for {
		select {
		case <-n.ctx.Done():
			n.logger.Debug("context canceled")
			return
		case <-n.stopCh:
			n.logger.Debug("termination requested")
			return
		case dsc := <-dscCh:
			// We only care about TEE-enabled runtimes.
			if dsc.TEEHardware != node.TEEHardwareIntelSGX {
				continue
			}

			var epoch beacon.EpochTime
			epoch, err = n.consensus.Beacon().GetEpoch(n.ctx, consensus.HeightLatest)
			if err != nil {
				n.logger.Error("failed to query current epoch",
					"err", err,
				)
				continue
			}

			// Fetch the active deployment.
			vi := dsc.ActiveDeployment(epoch)
			if vi == nil {
				continue
			}

			// Parse SGX constraints.
			var sc node.SGXConstraints
			if err = cbor.Unmarshal(vi.TEE, &sc); err != nil {
				n.logger.Error("malformed SGX constraints",
					"err", err,
				)
				continue
			}

			// Apply defaults.
			var params *registry.ConsensusParameters
			params, err = n.consensus.Registry().ConsensusParameters(n.ctx, consensus.HeightLatest)
			if err != nil {
				n.logger.Error("failed to query registry parameters",
					"err", err,
				)
				continue
			}
			if params.TEEFeatures != nil {
				params.TEEFeatures.SGX.ApplyDefaultConstraints(&sc)
			}

			// Pick a random interval between 50% and 90% of the MaxAttestationAge.
			if sc.MaxAttestationAge > 2 { // Ensure a is non-zero.
				a := (sc.MaxAttestationAge * 4) / 10 // 40%
				b := sc.MaxAttestationAge / 2        // 50%
				maxAttestationAge = b + uint64(rand.Int63n(int64(a)))
			} else {
				maxAttestationAge = 0 // Disarm height-based re-attestation.
			}
		case rawBlk, ok := <-blkCh.Out():
			// New consensus layer block.
			if !ok {
				return
			}
			blk := rawBlk.(*consensus.Block)
			height := uint64(blk.Height)

			// Notify the runtime that a new consensus layer block is available.
			ctx, cancel := context.WithTimeout(n.ctx, notifyTimeout)
			err = n.host.ConsensusSync(ctx, height)
			cancel()
			if err != nil {
				n.logger.Error("failed to notify runtime of a new consensus layer block",
					"err", err,
					"height", height,
				)
				continue
			}
			n.logger.Debug("runtime notified of new consensus layer block",
				"height", height,
			)

			// Assume runtime has already done the initial attestation.
			if lastAttestationUpdate.IsZero() {
				lastAttestationUpdateHeight = height
				lastAttestationUpdate = time.Now()
			}
			// Periodically trigger re-attestation.
			if maxAttestationAge > 0 && height-lastAttestationUpdateHeight > maxAttestationAge &&
				time.Since(lastAttestationUpdate) > minAttestationInterval {

				n.logger.Debug("requesting the runtime to update CapabilityTEE")

				n.host.UpdateCapabilityTEE()
				lastAttestationUpdateHeight = height
				lastAttestationUpdate = time.Now()
			}
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
