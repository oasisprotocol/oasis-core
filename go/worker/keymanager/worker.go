package keymanager

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	rpcCallTimeout = 5 * time.Second
)

var (
	_ service.BackgroundService = (*Worker)(nil)

	errMalformedResponse = fmt.Errorf("worker/keymanager: malformed response from worker")
)

// The key manager worker.
//
// It behaves differently from other workers as the key manager has its
// own runtime. It needs to keep track of executor committees for other
// runtimes in order to update the access control lists.
type Worker struct { // nolint: maligned
	sync.RWMutex
	*runtimeRegistry.RuntimeHostNode

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	quitCh    chan struct{}
	initCh    chan struct{}

	initTicker   *backoff.Ticker
	initTickerCh <-chan time.Time

	runtime            runtimeRegistry.Runtime
	runtimeHostHandler protocol.Handler

	clientRuntimes       map[common.Namespace]*clientRuntimeWatcher
	clientRuntimesQuitCh chan *clientRuntimeWatcher

	commonWorker  *workerCommon.Worker
	roleProvider  registration.RoleProvider
	enclaveStatus *api.SignedInitResponse
	backend       api.Backend

	grpcPolicy *policy.DynamicRuntimePolicyChecker

	enabled     bool
	mayGenerate bool
}

func (w *Worker) Name() string {
	return "key manager worker"
}

func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting key manager worker as it is disabled")
		close(w.initCh)

		return nil
	}

	w.logger.Info("starting key manager worker")
	go w.worker()

	return nil
}

func (w *Worker) Stop() {
	w.logger.Info("stopping key manager service")

	if !w.enabled {
		return
	}

	// Stop the sub-components.
	w.cancelCtx()
	close(w.stopCh)
}

// Enabled returns if worker is enabled.
func (w *Worker) Enabled() bool {
	return w.enabled
}

func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

func (w *Worker) Cleanup() {
}

// Initialized returns a channel that will be closed when the worker is initialized, ready to
// service requests and registered with the consensus layer.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// Implements workerCommon.RuntimeHostHandlerFactory.
func (w *Worker) GetRuntime() runtimeRegistry.Runtime {
	return w.runtime
}

// Implements workerCommon.RuntimeHostHandlerFactory.
func (w *Worker) NewNotifier(ctx context.Context, host host.Runtime) protocol.Notifier {
	return &protocol.NoOpNotifier{}
}

// Implements workerCommon.RuntimeHostHandlerFactory.
func (w *Worker) NewRuntimeHostHandler() protocol.Handler {
	return w.runtimeHostHandler
}

func (w *Worker) callLocal(ctx context.Context, data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	// Wait for initialization to complete.
	select {
	case <-w.initCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	req := &protocol.Body{
		RuntimeRPCCallRequest: &protocol.RuntimeRPCCallRequest{
			Request: data,
		},
	}

	// NOTE: Hosted runtime should not be nil as we wait for initialization above.
	rt := w.GetHostedRuntime()
	response, err := rt.Call(ctx, req)
	if err != nil {
		w.logger.Error("failed to dispatch RPC call to runtime",
			"err", err,
		)
		return nil, err
	}

	resp := response.RuntimeRPCCallResponse
	if resp == nil {
		w.logger.Error("malformed response from runtime",
			"response", response,
		)
		return nil, errMalformedResponse
	}

	return resp.Response, nil
}

func (w *Worker) updateStatus(status *api.Status, startedEvent *host.StartedEvent) error {
	var initOk bool
	defer func() {
		if !initOk {
			// If initialization failed setup a retry ticker.
			if w.initTicker == nil {
				w.initTicker = backoff.NewTicker(backoff.NewExponentialBackOff())
				w.initTickerCh = w.initTicker.C
			}
		}
	}()

	// Initialize the key manager.
	type InitRequest struct {
		Checksum    []byte `json:"checksum"`
		Policy      []byte `json:"policy"`
		MayGenerate bool   `json:"may_generate"`
	}
	type InitCall struct { // nolint: maligned
		Method string      `json:"method"`
		Args   InitRequest `json:"args"`
	}

	var policy []byte
	if status.Policy != nil {
		policy = cbor.Marshal(status.Policy)
	}

	call := InitCall{
		Method: "init",
		Args: InitRequest{
			Checksum:    cbor.FixSliceForSerde(status.Checksum),
			Policy:      cbor.FixSliceForSerde(policy),
			MayGenerate: w.mayGenerate,
		},
	}
	req := &protocol.Body{
		RuntimeLocalRPCCallRequest: &protocol.RuntimeLocalRPCCallRequest{
			Request: cbor.Marshal(&call),
		},
	}

	rt := w.GetHostedRuntime()
	response, err := rt.Call(w.ctx, req)
	if err != nil {
		w.logger.Error("failed to initialize enclave",
			"err", err,
		)
		return err
	}

	resp := response.RuntimeLocalRPCCallResponse
	if resp == nil {
		w.logger.Error("malformed response initializing enclave",
			"response", response,
		)
		return errMalformedResponse
	}

	innerResp, err := extractMessageResponsePayload(resp.Response)
	if err != nil {
		w.logger.Error("failed to extract rpc response payload",
			"err", err,
		)
		return fmt.Errorf("worker/keymanager: failed to extract rpc response payload: %w", err)
	}

	var signedInitResp api.SignedInitResponse
	if err = cbor.Unmarshal(innerResp, &signedInitResp); err != nil {
		w.logger.Error("failed to parse response initializing enclave",
			"err", err,
			"response", innerResp,
		)
		return fmt.Errorf("worker/keymanager: failed to parse response initializing enclave: %w", err)
	}

	// Validate the signature.
	if tee := startedEvent.CapabilityTEE; tee != nil {
		var signingKey signature.PublicKey

		switch tee.Hardware {
		case node.TEEHardwareInvalid:
			signingKey = api.TestPublicKey
		case node.TEEHardwareIntelSGX:
			signingKey = tee.RAK
		default:
			return fmt.Errorf("worker/keymanager: unknown TEE hardware: %v", tee.Hardware)
		}

		if err = signedInitResp.Verify(signingKey); err != nil {
			return fmt.Errorf("worker/keymanager: failed to validate initialization response signature: %w", err)
		}
	}

	if !signedInitResp.InitResponse.IsSecure {
		w.logger.Warn("Key manager enclave build is INSECURE")
	}

	w.logger.Info("Key manager initialized",
		"checksum", hex.EncodeToString(signedInitResp.InitResponse.Checksum),
	)
	if w.initTicker != nil {
		w.initTickerCh = nil
		w.initTicker.Stop()
		w.initTicker = nil
	}

	// Register as we are now ready to handle requests.
	initOk = true
	w.roleProvider.SetAvailableWithCallback(func(n *node.Node) error {
		rt := n.AddOrUpdateRuntime(w.runtime.ID())
		rt.Version = startedEvent.Version
		rt.ExtraInfo = cbor.Marshal(signedInitResp)
		rt.Capabilities.TEE = startedEvent.CapabilityTEE
		return nil
	}, func(context.Context) error {
		w.logger.Info("Key manager registered")

		// Signal that we are initialized.
		select {
		case <-w.initCh:
		default:
			close(w.initCh)
		}
		return nil
	})

	// Cache the key manager enclave status.
	w.Lock()
	defer w.Unlock()

	w.enclaveStatus = &signedInitResp

	return nil
}

func extractMessageResponsePayload(raw []byte) ([]byte, error) {
	// See: runtime/src/rpc/types.rs
	type MessageResponseBody struct {
		Success interface{} `json:",omitempty"`
		Error   *string     `json:",omitempty"`
	}
	type MessageResponse struct {
		Response *struct {
			Body MessageResponseBody `json:"body"`
		}
	}

	var msg MessageResponse
	if err := cbor.Unmarshal(raw, &msg); err != nil {
		return nil, fmt.Errorf("malformed message envelope: %w", err)
	}

	if msg.Response == nil {
		return nil, fmt.Errorf("message is not a response: '%s'", hex.EncodeToString(raw))
	}

	switch {
	case msg.Response.Body.Success != nil:
	case msg.Response.Body.Error != nil:
		return nil, fmt.Errorf("rpc failure: '%s'", *msg.Response.Body.Error)
	default:
		return nil, fmt.Errorf("unknown rpc response status: '%s'", hex.EncodeToString(raw))
	}

	return cbor.Marshal(msg.Response.Body.Success), nil
}

func (w *Worker) startClientRuntimeWatcher(rt *registry.Runtime, status *api.Status) error {
	runtimeID := w.runtime.ID()
	if status == nil || !status.IsInitialized {
		return nil
	}
	if rt.Kind != registry.KindCompute || rt.KeyManager == nil || !rt.KeyManager.Equal(&runtimeID) {
		return nil
	}
	if w.clientRuntimes[rt.ID] != nil {
		return nil
	}
	w.logger.Info("seen new runtime using us as a key manager",
		"runtime_id", rt.ID,
	)

	// Check policy document if runtime is allowed to query any of the
	// key manager enclaves.
	var found bool
	switch {
	case !status.IsSecure && status.Policy == nil:
		// Insecure test keymanagers can be without a policy.
		found = true
	case status.Policy != nil:
		for _, enc := range status.Policy.Policy.Enclaves {
			if _, ok := enc.MayQuery[rt.ID]; ok {
				found = true
				break
			}
		}
	}
	if !found {
		w.logger.Warn("runtime not found in keymanager policy, skipping",
			"runtime_id", rt.ID,
			"status", status,
		)
		return nil
	}

	runtimeUnmg, err := w.commonWorker.RuntimeRegistry.NewUnmanagedRuntime(w.ctx, rt.ID)
	if err != nil {
		w.logger.Error("unable to create new unmanaged runtime",
			"err", err,
		)
		return err
	}
	node, err := w.commonWorker.NewUnmanagedCommitteeNode(runtimeUnmg, false)
	if err != nil {
		w.logger.Error("unable to create new committee node",
			"runtime_id", rt.ID,
			"err", err,
		)
		return err
	}

	crw := &clientRuntimeWatcher{
		w:    w,
		node: node,
	}
	node.AddHooks(crw)

	if err := node.Start(); err != nil {
		w.logger.Error("unable to start new committee node",
			"runtime_id", rt.ID,
			"err", err,
		)
		return err
	}

	go func() {
		select {
		case <-node.Quit():
			w.clientRuntimesQuitCh <- crw
		case <-w.stopCh:
		}
	}()

	w.clientRuntimes[rt.ID] = crw

	return nil
}

func (w *Worker) recheckAllRuntimes(status *api.Status) error {
	rts, err := w.commonWorker.Consensus.Registry().GetRuntimes(w.ctx,
		&registry.GetRuntimesQuery{
			Height:           consensus.HeightLatest,
			IncludeSuspended: false,
		},
	)
	if err != nil {
		w.logger.Error("failed querying runtimes",
			"err", err,
		)
		return fmt.Errorf("failed querying runtimes: %w", err)
	}
	for _, rt := range rts {
		if err := w.startClientRuntimeWatcher(rt, status); err != nil {
			w.logger.Error("failed to start runtime watcher",
				"err", err,
			)
			continue
		}
	}

	return nil
}

func (w *Worker) worker() { // nolint: gocyclo
	defer close(w.quitCh)

	// Wait for consensus sync.
	w.logger.Info("delaying worker start until after initial synchronization")
	select {
	case <-w.stopCh:
		return
	case <-w.commonWorker.Consensus.Synced():
	}

	// Need to explicitly watch for updates related to the key manager runtime
	// itself.
	knw := newKmNodeWatcher(w)
	go knw.watchNodes()

	// Subscribe to key manager status updates.
	statusCh, statusSub := w.backend.WatchStatuses()
	defer statusSub.Close()

	// Subscribe to runtime registrations in order to know which runtimes
	// are using us as a key manager.
	w.clientRuntimes = make(map[common.Namespace]*clientRuntimeWatcher)
	w.clientRuntimesQuitCh = make(chan *clientRuntimeWatcher)
	defer func() {
		for _, crw := range w.clientRuntimes {
			crw.node.Stop()
			<-crw.node.Quit()
		}
	}()

	rtCh, rtSub, err := w.commonWorker.Consensus.Registry().WatchRuntimes(w.ctx)
	if err != nil {
		w.logger.Error("failed to watch runtimes",
			"err", err,
		)
		return
	}
	defer rtSub.Close()

	var (
		hrtEventCh          <-chan *host.Event
		currentStatus       *api.Status
		currentStartedEvent *host.StartedEvent

		runtimeID = w.runtime.ID()
	)
	for {
		select {
		case ev := <-hrtEventCh:
			switch {
			case ev.Started != nil, ev.Updated != nil:
				// Runtime has started successfully.
				currentStartedEvent = ev.Started
				if currentStatus == nil {
					continue
				}

				// Send a node preregistration, so that other nodes know to update their access
				// control.
				if w.enclaveStatus == nil {
					w.roleProvider.SetAvailable(func(n *node.Node) error {
						rt := n.AddOrUpdateRuntime(w.runtime.ID())
						rt.Version = currentStartedEvent.Version
						rt.ExtraInfo = nil
						rt.Capabilities.TEE = currentStartedEvent.CapabilityTEE
						return nil
					})
				}

				// Forward status update to key manager runtime.
				if err = w.updateStatus(currentStatus, currentStartedEvent); err != nil {
					w.logger.Error("failed to handle status update",
						"err", err,
					)
					continue
				}
			case ev.FailedToStart != nil, ev.Stopped != nil:
				// Worker failed to start or was stopped -- we can no longer service requests.
				currentStartedEvent = nil
				w.roleProvider.SetUnavailable()
			default:
				// Unknown event.
				w.logger.Warn("unknown worker event",
					"ev", ev,
				)
			}
		case status := <-statusCh:
			if !status.ID.Equal(&runtimeID) {
				continue
			}

			w.logger.Info("received key manager status update")

			// Check if this is the first update and we need to initialize the
			// worker host.
			hrt := w.GetHostedRuntime()
			if hrt == nil {
				// Start key manager runtime.
				w.logger.Info("provisioning key manager runtime")

				var hrtNotifier protocol.Notifier
				hrt, hrtNotifier, err = w.ProvisionHostedRuntime(w.ctx)
				if err != nil {
					w.logger.Error("failed to provision key manager runtime",
						"err", err,
					)
					return
				}

				var sub pubsub.ClosableSubscription
				if hrtEventCh, sub, err = hrt.WatchEvents(w.ctx); err != nil {
					w.logger.Error("failed to subscribe to runtime events",
						"err", err,
					)
					return
				}
				defer sub.Close()

				if err = hrt.Start(); err != nil {
					w.logger.Error("failed to start runtime",
						"err", err,
					)
					return
				}
				defer hrt.Stop()

				if err = hrtNotifier.Start(); err != nil {
					w.logger.Error("failed to start runtime notifier",
						"err", err,
					)
					return
				}
				defer hrtNotifier.Stop()
			}

			currentStatus = status
			if currentStartedEvent == nil {
				continue
			}

			// Forward status update to key manager runtime.
			if err = w.updateStatus(currentStatus, currentStartedEvent); err != nil {
				w.logger.Error("failed to handle status update",
					"err", err,
				)
				continue
			}
			// New runtimes can be allowed with the policy update.
			if err = w.recheckAllRuntimes(currentStatus); err != nil {
				w.logger.Error("failed rechecking runtimes",
					"err", err,
				)
				continue
			}
		case <-w.initTickerCh:
			if currentStatus == nil || currentStartedEvent == nil {
				continue
			}
			if err = w.updateStatus(currentStatus, currentStartedEvent); err != nil {
				w.logger.Error("failed to handle status update", "err", err)
				continue
			}
			// New runtimes can be allowed with the policy update.
			if err = w.recheckAllRuntimes(currentStatus); err != nil {
				w.logger.Error("failed rechecking runtimes",
					"err", err,
				)
				continue
			}
		case rt := <-rtCh:
			if err = w.startClientRuntimeWatcher(rt, currentStatus); err != nil {
				w.logger.Error("failed to start runtime watcher",
					"err", err,
				)
				continue
			}
		case crw := <-w.clientRuntimesQuitCh:
			w.logger.Error("client runtime watcher quit unexpectedly, terminating",
				"runtme_id", crw.node.Runtime.ID(),
			)
			return
		case <-w.stopCh:
			w.logger.Info("termination requested")
			return
		}
	}
}

type clientRuntimeWatcher struct {
	w    *Worker
	node *committeeCommon.Node
}

func (crw *clientRuntimeWatcher) HandlePeerMessage(context.Context, *p2p.Message, bool) (bool, error) {
	// This should never be called as P2P is disabled.
	panic("keymanager/worker: must never be called")
}

func (crw *clientRuntimeWatcher) updateExternalServicePolicyLocked(snapshot *committeeCommon.EpochSnapshot) {
	// Update key manager access control policy on epoch transitions.
	policy := accessctl.NewPolicy()

	// Apply rules to current executor committee members.
	if xc := snapshot.GetExecutorCommittee(); xc != nil {
		executorCommitteePolicy.AddRulesForCommittee(&policy, xc, snapshot.Nodes())
	}

	// Apply rules for configured sentry nodes.
	for _, addr := range crw.w.commonWorker.GetConfig().SentryAddresses {
		sentryNodesPolicy.AddPublicKeyPolicy(&policy, addr.PubKey)
	}

	crw.w.grpcPolicy.SetAccessPolicy(policy, crw.node.Runtime.ID())
	crw.w.logger.Debug("worker/keymanager: new normal runtime access policy in effect", "policy", policy)
}

// Guarded by CrossNode.
func (crw *clientRuntimeWatcher) HandleEpochTransitionLocked(snapshot *committeeCommon.EpochSnapshot) {
	crw.updateExternalServicePolicyLocked(snapshot)
}

// Guarded by CrossNode.
func (crw *clientRuntimeWatcher) HandleNewBlockEarlyLocked(*block.Block) {
	// Nothing to do here.
}

// Guarded by CrossNode.
func (crw *clientRuntimeWatcher) HandleNewBlockLocked(*block.Block) {
	// Nothing to do here.
}

// Guarded by CrossNode.
func (crw *clientRuntimeWatcher) HandleNewEventLocked(*roothash.Event) {
	// Nothing to do here.
}

// Guarded by CrossNode.
func (crw *clientRuntimeWatcher) HandleNodeUpdateLocked(update *nodes.NodeUpdate, snapshot *committeeCommon.EpochSnapshot) {
	crw.updateExternalServicePolicyLocked(snapshot)
}
