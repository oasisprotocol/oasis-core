package keymanager

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/grpc/policy"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/service"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	runtimeCommittee "github.com/oasislabs/oasis-core/go/runtime/committee"
	"github.com/oasislabs/oasis-core/go/runtime/host"
	"github.com/oasislabs/oasis-core/go/runtime/host/protocol"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	committeeCommon "github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

const (
	rpcCallTimeout = 5 * time.Second
)

var (
	_ service.BackgroundService = (*Worker)(nil)

	errMalformedResponse = fmt.Errorf("worker/keymanager: malformed response from worker")

	emptyRoot hash.Hash
)

// The key manager worker.
//
// It behaves differently from other workers as the key manager has its
// own runtime. It needs to keep track of executor committees for other
// runtimes in order to update the access control lists.
type Worker struct { // nolint: maligned
	sync.RWMutex
	*workerCommon.RuntimeHostNode

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	quitCh    chan struct{}
	initCh    chan struct{}

	initialSyncDone bool

	runtime            runtimeRegistry.Runtime
	runtimeHostHandler protocol.Handler

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

// Implements workerCommon.RuntimeHostHandlerFactory.
func (w *Worker) GetRuntime() runtimeRegistry.Runtime {
	return w.runtime
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
			Request:   data,
			StateRoot: emptyRoot,
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

	if response.Error != nil {
		w.logger.Error("error from runtime",
			"err", response.Error.Message,
		)
		return nil, fmt.Errorf("worker/keymanager: error from runtime: %s", response.Error.Message)
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
			// This is likely a new key manager that needs to replicate.
			// Send a node registration anyway, so that other nodes know
			// to update their access control.
			w.roleProvider.SetAvailable(func(n *node.Node) error {
				rt := n.AddOrUpdateRuntime(w.runtime.ID())
				rt.Version = startedEvent.Version
				rt.ExtraInfo = nil
				rt.Capabilities.TEE = startedEvent.CapabilityTEE
				return nil
			})
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
			Request:   cbor.Marshal(&call),
			StateRoot: emptyRoot,
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
	if response.Error != nil {
		w.logger.Error("error initializing enclave",
			"err", response.Error.Message,
		)
		return fmt.Errorf("worker/keymanager: error initializing enclave: %s", response.Error.Message)
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
			return fmt.Errorf("worker/keymanager: failed to validate initialziation response signature: %w", err)
		}
	}

	if !signedInitResp.InitResponse.IsSecure {
		w.logger.Warn("Key manager enclave build is INSECURE")
	}

	w.logger.Info("Key manager initialized",
		"checksum", hex.EncodeToString(signedInitResp.InitResponse.Checksum),
	)

	// Register as we are now ready to handle requests.
	initOk = true
	w.roleProvider.SetAvailable(func(n *node.Node) error {
		rt := n.AddOrUpdateRuntime(w.runtime.ID())
		rt.Version = startedEvent.Version
		rt.ExtraInfo = cbor.Marshal(signedInitResp)
		rt.Capabilities.TEE = startedEvent.CapabilityTEE
		return nil
	})

	// Cache the key manager enclave status.
	w.Lock()
	defer w.Unlock()

	w.enclaveStatus = &signedInitResp

	if !w.initialSyncDone {
		// Signal that we are initialized.
		close(w.initCh)
		w.initialSyncDone = true
	}

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
	clientRuntimes := make(map[common.Namespace]*clientRuntimeWatcher)
	clientRuntimesQuitCh := make(chan *clientRuntimeWatcher)
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

				hrt, err = w.ProvisionHostedRuntime(w.ctx)
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
			}

			currentStatus = status
			if currentStartedEvent == nil {
				continue
			}

			// Forward status update to key manager runtime.
			if err := w.updateStatus(currentStatus, currentStartedEvent); err != nil {
				w.logger.Error("failed to handle status update",
					"err", err,
				)
				continue
			}
		case rt := <-rtCh:
			if rt.Kind != registry.KindCompute || rt.KeyManager == nil || !rt.KeyManager.Equal(&runtimeID) {
				continue
			}
			if clientRuntimes[rt.ID] != nil {
				continue
			}

			w.logger.Info("seen new runtime using us as a key manager",
				"runtime_id", rt.ID,
			)

			runtimeUnmg, err := w.commonWorker.RuntimeRegistry.NewUnmanagedRuntime(w.ctx, rt.ID)
			if err != nil {
				w.logger.Error("unable to create new unmanaged runtime",
					"err", err,
				)
				continue
			}
			node, err := w.commonWorker.NewUnmanagedCommitteeNode(runtimeUnmg, false)
			if err != nil {
				w.logger.Error("unable to create new committee node",
					"runtime_id", rt.ID,
					"err", err,
				)
				continue
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
				continue
			}
			defer func() {
				node.Stop()
				<-node.Quit()
			}()
			go func() {
				select {
				case <-node.Quit():
					clientRuntimesQuitCh <- crw
				case <-w.stopCh:
				}
			}()

			clientRuntimes[rt.ID] = crw
		case crw := <-clientRuntimesQuitCh:
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

func (crw *clientRuntimeWatcher) HandlePeerMessage(context.Context, *p2p.Message) (bool, error) {
	// This should never be called as P2P is disabled.
	panic("keymanager/worker: must never be called")
}

func (crw *clientRuntimeWatcher) updateExternalServicePolicyLocked(snapshot *committeeCommon.EpochSnapshot) {
	// Update key manager access control policy on epoch transitions.
	policy := accessctl.NewPolicy()

	// Apply rules to current executor committee members.
	for _, xc := range snapshot.GetExecutorCommittees() {
		if xc != nil {
			executorCommitteePolicy.AddRulesForCommittee(&policy, xc, snapshot.Nodes())
		}
	}

	// Apply rules for configured sentry nodes.
	sentryCerts := crw.w.commonWorker.GetConfig().SentryCertificates
	for _, cert := range sentryCerts {
		sentryNodesPolicy.AddCertPolicy(&policy, cert)
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
func (crw *clientRuntimeWatcher) HandleNodeUpdateLocked(update *runtimeCommittee.NodeUpdate, snapshot *committeeCommon.EpochSnapshot) {
	crw.updateExternalServicePolicyLocked(snapshot)
}
