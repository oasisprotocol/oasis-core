package keymanager

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	p2p "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	rpcCallTimeout = 2 * time.Second

	// Make sure this always matches the appropriate method in
	// `keymanager-runtime/src/methods.rs`.
	getPublicKeyRequestMethod          = "get_public_key"
	getPublicEphemeralKeyRequestMethod = "get_public_ephemeral_key"
)

var (
	_ service.BackgroundService = (*Worker)(nil)

	errMalformedResponse = fmt.Errorf("worker/keymanager: malformed response from worker")
)

type runtimeStatus struct {
	version       version.Version
	capabilityTEE *node.CapabilityTEE
}

// Worker is the key manager worker.
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

	runtime runtimeRegistry.Runtime

	clientRuntimes map[common.Namespace]*clientRuntimeWatcher

	accessList          map[core.PeerID]map[common.Namespace]struct{}
	accessListByRuntime map[common.Namespace][]core.PeerID
	privatePeers        map[core.PeerID]struct{}

	commonWorker  *workerCommon.Worker
	roleProvider  registration.RoleProvider
	enclaveStatus *api.SignedInitResponse
	backend       api.Backend

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
		close(w.quitCh)
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

func (w *Worker) CallEnclave(ctx context.Context, data []byte) ([]byte, error) {
	// Handle access control as only peers on the access list can call this method.
	peerID, ok := rpc.PeerIDFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("not authorized")
	}

	// Peek into the frame data to extract the method.
	var frame enclaverpc.Frame
	if err := cbor.Unmarshal(data, &frame); err != nil {
		return nil, fmt.Errorf("malformed request")
	}

	// Note that the untrusted plaintext is also checked in the enclave, so if the node lied about
	// what method it's using, we will know and the request will get rejected.
	switch frame.UntrustedPlaintext {
	case "":
		// Anyone can connect.
	case getPublicKeyRequestMethod, getPublicEphemeralKeyRequestMethod:
		// Anyone can get public keys.
	default:
		if _, privatePeered := w.privatePeers[peerID]; !privatePeered {
			// Defer to access control to check the policy.
			w.RLock()
			_, allowed := w.accessList[peerID]
			w.RUnlock()
			if !allowed {
				return nil, fmt.Errorf("not authorized")
			}
		}
	}

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

func (w *Worker) updateStatus(status *api.Status, runtimeStatus *runtimeStatus) error {
	var initOk bool
	defer func() {
		if !initOk {
			// If initialization failed setup a retry ticker.
			if w.initTicker == nil {
				w.initTicker = backoff.NewTicker(cmnBackoff.NewExponentialBackOff())
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
	if tee := runtimeStatus.capabilityTEE; tee != nil {
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

	policyUpdateCount.Inc()

	// Register as we are now ready to handle requests.
	initOk = true
	w.roleProvider.SetAvailableWithCallback(func(n *node.Node) error {
		rt := n.AddOrUpdateRuntime(w.runtime.ID(), runtimeStatus.version)
		rt.Version = runtimeStatus.version
		rt.ExtraInfo = cbor.Marshal(signedInitResp)
		rt.Capabilities.TEE = runtimeStatus.capabilityTEE
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

func (w *Worker) addClientRuntimeWatcher(n common.Namespace, crw *clientRuntimeWatcher) {
	w.Lock()
	defer w.Unlock()

	w.clientRuntimes[n] = crw
}

func (w *Worker) getClientRuntimeWatcher(n common.Namespace) *clientRuntimeWatcher {
	w.RLock()
	defer w.RUnlock()

	return w.clientRuntimes[n]
}

func (w *Worker) getClientRuntimeWatchers() []*clientRuntimeWatcher {
	w.RLock()
	defer w.RUnlock()

	crws := make([]*clientRuntimeWatcher, 0, len(w.clientRuntimes))
	for _, crw := range w.clientRuntimes {
		crws = append(crws, crw)
	}

	return crws
}

func (w *Worker) startClientRuntimeWatcher(rt *registry.Runtime, status *api.Status) error {
	runtimeID := w.runtime.ID()
	if status == nil || !status.IsInitialized {
		return nil
	}
	if rt.Kind != registry.KindCompute || rt.KeyManager == nil || !rt.KeyManager.Equal(&runtimeID) {
		return nil
	}
	if w.getClientRuntimeWatcher(rt.ID) != nil {
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

	nodes, err := nodes.NewVersionedNodeDescriptorWatcher(w.ctx, w.commonWorker.Consensus)
	if err != nil {
		w.logger.Error("unable to create new client runtime node watcher",
			"err", err,
			"runtime_id", rt.ID,
		)
		return err
	}
	crw := &clientRuntimeWatcher{
		w:         w,
		runtimeID: rt.ID,
		nodes:     nodes,
	}
	crw.epochTransition()
	go crw.worker()

	w.addClientRuntimeWatcher(rt.ID, crw)

	computeRuntimeCount.Inc()

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

func (w *Worker) setAccessList(runtimeID common.Namespace, nodes []*node.Node) {
	w.Lock()
	defer w.Unlock()

	// Clear any old nodes from the access list.
	for _, peerID := range w.accessListByRuntime[runtimeID] {
		entry := w.accessList[peerID]
		delete(entry, runtimeID)
		if len(entry) == 0 {
			delete(w.accessList, peerID)
		}
	}

	// Update the access list.
	var peers []core.PeerID
	for _, node := range nodes {
		peerID, err := p2p.PublicKeyToPeerID(node.P2P.ID)
		if err != nil {
			w.logger.Warn("invalid node P2P ID",
				"err", err,
				"node_id", node.ID,
			)
			continue
		}

		entry := w.accessList[peerID]
		if entry == nil {
			entry = make(map[common.Namespace]struct{})
			w.accessList[peerID] = entry
		}

		entry[runtimeID] = struct{}{}
		peers = append(peers, peerID)
	}
	w.accessListByRuntime[runtimeID] = peers

	w.logger.Debug("new client runtime access policy in effect",
		"runtime_id", runtimeID,
		"peers", peers,
	)
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

	// Subscribe to epoch transitions in order to know when we need to refresh
	// the access control policy.
	epoCh, epoSub, err := w.commonWorker.Consensus.Beacon().WatchLatestEpoch(w.ctx)
	if err != nil {
		w.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer epoSub.Close()

	// Subscribe to runtime registrations in order to know which runtimes
	// are using us as a key manager.
	rtCh, rtSub, err := w.commonWorker.Consensus.Registry().WatchRuntimes(w.ctx)
	if err != nil {
		w.logger.Error("failed to watch runtimes",
			"err", err,
		)
		return
	}
	defer rtSub.Close()

	var (
		hrtEventCh           <-chan *host.Event
		currentStatus        *api.Status
		currentRuntimeStatus *runtimeStatus

		runtimeID = w.runtime.ID()
	)
	for {
		select {
		case ev := <-hrtEventCh:
			switch {
			case ev.Started != nil, ev.Updated != nil:
				// Runtime has started successfully.
				currentRuntimeStatus = &runtimeStatus{}
				switch {
				case ev.Started != nil:
					currentRuntimeStatus.version = ev.Started.Version
					currentRuntimeStatus.capabilityTEE = ev.Started.CapabilityTEE
				case ev.Updated != nil:
					currentRuntimeStatus.version = ev.Updated.Version
					currentRuntimeStatus.capabilityTEE = ev.Updated.CapabilityTEE
				default:
					continue
				}

				if currentStatus == nil {
					continue
				}

				// Send a node preregistration, so that other nodes know to update their access
				// control.
				if w.enclaveStatus == nil {
					w.roleProvider.SetAvailable(func(n *node.Node) error {
						rt := n.AddOrUpdateRuntime(w.runtime.ID(), currentRuntimeStatus.version)
						rt.Version = currentRuntimeStatus.version
						rt.ExtraInfo = nil
						rt.Capabilities.TEE = currentRuntimeStatus.capabilityTEE
						return nil
					})
				}

				// Forward status update to key manager runtime.
				if err = w.updateStatus(currentStatus, currentRuntimeStatus); err != nil {
					w.logger.Error("failed to handle status update",
						"err", err,
					)
					continue
				}
			case ev.FailedToStart != nil, ev.Stopped != nil:
				// Worker failed to start or was stopped -- we can no longer service requests.
				currentRuntimeStatus = nil
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

				// Key managers always need to use the enclave version given to them in the bundle
				// as they need to make sure that replication is possible during upgrades.
				activeVersion := w.runtime.HostVersions()[0] // Init made sure we have exactly one.
				if err = w.SetHostedRuntimeVersion(w.ctx, activeVersion); err != nil {
					w.logger.Error("failed to activate runtime version",
						"err", err,
						"version", activeVersion,
					)
					return
				}
			}

			currentStatus = status
			if currentRuntimeStatus == nil {
				continue
			}

			// Forward status update to key manager runtime.
			if err = w.updateStatus(currentStatus, currentRuntimeStatus); err != nil {
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
			if currentStatus == nil || currentRuntimeStatus == nil {
				continue
			}
			if err = w.updateStatus(currentStatus, currentRuntimeStatus); err != nil {
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
		case <-epoCh:
			for _, crw := range w.getClientRuntimeWatchers() {
				crw.epochTransition()
			}
		case <-w.stopCh:
			w.logger.Info("termination requested")
			return
		}
	}
}

type clientRuntimeWatcher struct {
	w         *Worker
	runtimeID common.Namespace
	nodes     nodes.VersionedNodeDescriptorWatcher
}

func (crw *clientRuntimeWatcher) worker() {
	ch, sub, err := crw.nodes.WatchNodeUpdates()
	if err != nil {
		crw.w.logger.Error("failed to subscribe to client runtime node updates",
			"err", err,
			"runtime_id", crw.runtimeID,
		)
		return
	}
	defer sub.Close()

	for {
		select {
		case <-crw.w.ctx.Done():
			return
		case nu := <-ch:
			if nu.Reset {
				// Ignore reset events to avoid clearing the access list before setting a new one.
				// This is safe because a reset event is always followed by a freeze event after the
				// nodes have been set (even if the new set is empty).
				continue
			}
			crw.w.setAccessList(crw.runtimeID, crw.nodes.GetNodes())
		}
	}
}

func (crw *clientRuntimeWatcher) epochTransition() {
	crw.nodes.Reset()

	cms, err := crw.w.commonWorker.Consensus.Scheduler().GetCommittees(crw.w.ctx, &scheduler.GetCommitteesRequest{
		Height:    consensus.HeightLatest,
		RuntimeID: crw.runtimeID,
	})
	if err != nil {
		crw.w.logger.Error("failed to fetch client runtime committee",
			"err", err,
			"runtime_id", crw.runtimeID,
		)
		return
	}

	for _, cm := range cms {
		if cm.Kind != scheduler.KindComputeExecutor {
			continue
		}

		for _, member := range cm.Members {
			_, _ = crw.nodes.WatchNode(crw.w.ctx, member.PublicKey)
		}
	}

	crw.nodes.Freeze(0)

	crw.w.setAccessList(crw.runtimeID, crw.nodes.GetNodes())
}
