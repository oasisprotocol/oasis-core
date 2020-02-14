package keymanager

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pkg/errors"

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
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	committeeCommon "github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/common/host"
	"github.com/oasislabs/oasis-core/go/worker/common/host/protocol"
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

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	quitCh    chan struct{}
	initCh    chan struct{}

	initialSyncDone bool

	runtimeID     common.Namespace
	workerHost    host.Host
	workerHostCfg host.Config

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

func (w *Worker) getWorkerHost() host.Host {
	w.RLock()
	defer w.RUnlock()

	return w.workerHost
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
		WorkerRPCCallRequest: &protocol.WorkerRPCCallRequest{
			Request:   data,
			StateRoot: emptyRoot,
		},
	}

	// NOTE: Worker host should not be nil as we wait for initialization above.
	workerHost := w.getWorkerHost()
	ch, err := workerHost.MakeRequest(ctx, req)
	if err != nil {
		w.logger.Error("failed to dispatch RPC call to worker host",
			"err", err,
		)
		return nil, err
	}

	select {
	case response := <-ch:
		if response == nil {
			w.logger.Error("channel closed during RPC call",
				"err", io.EOF,
			)
			return nil, errors.Wrap(io.EOF, "worker/keymanager: channel closed during RPC call")
		}

		if response.Error != nil {
			w.logger.Error("error from runtime",
				"err", response.Error.Message,
			)
			return nil, fmt.Errorf("worker/keymanager: error from runtime: %s", response.Error.Message)
		}

		resp := response.WorkerRPCCallResponse
		if resp == nil {
			w.logger.Error("malformed response from worker",
				"response", response,
			)
			return nil, errMalformedResponse
		}

		return resp.Response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-w.stopCh:
		return nil, fmt.Errorf("worker/keymanager: terminating")
	}
}

func (w *Worker) updateStatus(status *api.Status, startedEvent *host.StartedEvent) error {
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
		WorkerLocalRPCCallRequest: &protocol.WorkerLocalRPCCallRequest{
			Request:   cbor.Marshal(&call),
			StateRoot: emptyRoot,
		},
	}

	workerHost := w.getWorkerHost()
	response, err := workerHost.Call(w.ctx, req)
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

	resp := response.WorkerLocalRPCCallResponse
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
		return errors.Wrap(err, "worker/keymanager: failed to extract rpc response payload")
	}

	var signedInitResp api.SignedInitResponse
	if err = cbor.Unmarshal(innerResp, &signedInitResp); err != nil {
		w.logger.Error("failed to parse response initializing enclave",
			"err", err,
			"response", innerResp,
		)
		return errors.Wrap(err, "worker/keymanager: failed to parse response initializing enclave")
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
			return errors.Wrap(err, "worker/keymanager: failed to validate initialziation response signature")
		}
	}

	if !signedInitResp.InitResponse.IsSecure {
		w.logger.Warn("Key manager enclave build is INSECURE")
	}

	w.logger.Info("Key manager initialized",
		"checksum", hex.EncodeToString(signedInitResp.InitResponse.Checksum),
	)

	// Register as we are now ready to handle requests.
	w.roleProvider.SetAvailable(func(n *node.Node) error {
		rt := n.AddOrUpdateRuntime(w.runtimeID)
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
		return nil, errors.Wrap(err, "malformed message envelope")
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

	var workerHostCh <-chan *host.Event
	var currentStatus *api.Status
	var currentStartedEvent *host.StartedEvent
	for {
		select {
		case ev := <-workerHostCh:
			switch {
			case ev.Started != nil:
				// Runtime has started successfully.
				currentStartedEvent = ev.Started
				if currentStatus == nil {
					continue
				}

				// Forward status update to key manager runtime.
				if err := w.updateStatus(currentStatus, currentStartedEvent); err != nil {
					w.logger.Error("failed to handle status update",
						"err", err,
					)
					continue
				}
			case ev.FailedToStart != nil:
				// Worker failed to start -- we can no longer service requests.
				currentStartedEvent = nil
				w.roleProvider.SetUnavailable()
			default:
				// Unknown event.
				w.logger.Warn("unknown worker event",
					"ev", ev,
				)
			}
		case status := <-statusCh:
			if !status.ID.Equal(&w.runtimeID) {
				continue
			}

			w.logger.Info("received key manager status update")

			// Check if this is the first update and we need to initialize the
			// worker host.
			workerHost := w.getWorkerHost()
			if workerHost == nil {
				// Start key manager runtime worker host.
				w.logger.Info("starting key manager runtime")

				var err error
				workerHost, err = host.NewHost(&w.workerHostCfg)
				if err != nil {
					w.logger.Error("failed to create worker host",
						"err", err,
					)
					return
				}

				var sub pubsub.ClosableSubscription
				if workerHostCh, sub, err = workerHost.WatchEvents(w.ctx); err != nil {
					w.logger.Error("failed to subscribe to worker host events",
						"err", err,
					)
					return
				}
				defer sub.Close()

				if err := workerHost.Start(); err != nil {
					w.logger.Error("failed to start worker host",
						"err", err,
					)
					return
				}
				defer func() {
					workerHost.Stop()
					<-workerHost.Quit()
				}()

				w.Lock()
				w.workerHost = workerHost
				w.Unlock()
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
			if rt.Kind != registry.KindCompute || rt.KeyManager == nil || !rt.KeyManager.Equal(&w.runtimeID) {
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

	// Fetch current KM node public keys, get their nodes, apply rules.
	height := snapshot.GetGroupVersion()
	status, err := crw.w.backend.GetStatus(crw.w.ctx, crw.w.runtimeID, height)
	if err != nil {
		crw.w.logger.Error("worker/keymanager: unable to get KM status",
			"runtimeID", crw.w.runtimeID,
			"err", err)
	} else {
		var kmNodes []*node.Node

		for _, pk := range status.Nodes {
			n, err := crw.node.Consensus.Registry().GetNode(crw.w.ctx, &registry.IDQuery{ID: pk, Height: height})
			if err != nil {
				crw.w.logger.Error("worker/keymanager: unable to get KM node info", "err", err)
			} else {
				kmNodes = append(kmNodes, n)
			}
		}

		kmNodesPolicy.AddRulesForNodeRoles(&policy, kmNodes, node.RoleKeyManager)
	}

	crw.w.grpcPolicy.SetAccessPolicy(policy, crw.node.Runtime.ID())
	crw.w.logger.Debug("worker/keymanager: new access policy in effect", "policy", policy)
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
