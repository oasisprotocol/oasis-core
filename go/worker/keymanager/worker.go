package keymanager

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	committeeCommon "github.com/oasislabs/ekiden/go/worker/common/committee"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const rpcCallTimeout = 5 * time.Second

var (
	_ service.BackgroundService = (*Worker)(nil)

	errMalformedResponse = fmt.Errorf("worker/keymanager: malformed response from worker")

	emptyRoot hash.Hash
)

// The key manager worker.
//
// It behaves differently from other workers as the key manager has its
// own runtime. It needs to keep track of compute committees for other
// runtimes in order to update the access control lists.
type Worker struct {
	sync.RWMutex

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	quitCh    chan struct{}
	initCh    chan struct{}

	runtimeID     signature.PublicKey
	workerHost    host.Host
	workerHostCfg host.Config

	commonWorker  *workerCommon.Worker
	registration  *registration.Registration
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

func (w *Worker) updateStatus(status *api.Status) error {
	// Initialize the key manager.
	type InitRequest struct {
		Checksum    []byte `codec:"checksum"`
		Policy      []byte `codec:"policy"`
		MayGenerate bool   `codec:"may_generate"`
	}
	type InitCall struct { // nolint: maligned
		Method string      `codec:"method"`
		Args   InitRequest `codec:"args"`
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
	tee, err := workerHost.WaitForCapabilityTEE(w.ctx)
	if err != nil {
		w.logger.Error("failed to get TEE capability",
			"err", err,
		)
		return fmt.Errorf("worker/keymanager: failed to get TEE capability")
	}
	if tee != nil {
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

	// Cache the key manager enclave status.
	w.Lock()
	defer w.Unlock()

	w.enclaveStatus = &signedInitResp

	return nil
}

func extractMessageResponsePayload(raw []byte) ([]byte, error) {
	// See: runtime/src/rpc/types.rs
	type MessageResponseBody struct {
		Success interface{}
		Error   *string
	}
	type MessageResponse struct {
		Response *struct {
			Body MessageResponseBody `codec:"body"`
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

func (w *Worker) onNodeRegistration(n *node.Node) error {
	// Wait for initialization to complete.
	select {
	case <-w.initCh:
	case <-w.ctx.Done():
		return w.ctx.Err()
	}

	// NOTE: Worker host should not be nil as we wait for initialization above.
	workerHost := w.getWorkerHost()
	tee, err := workerHost.WaitForCapabilityTEE(w.ctx)
	if err != nil {
		w.logger.Error("failed to obtain CapabilityTEE",
			"err", err,
		)
		return err
	}

	// Pull out the enclave status to be appended to the node registration.
	w.Lock()
	enclaveStatus := w.enclaveStatus
	w.Unlock()
	if enclaveStatus == nil {
		w.logger.Error("enclave not initialized")
		return fmt.Errorf("worker/keymanager: enclave not initialized")
	}

	rtVersion, err := workerHost.WaitForRuntimeVersion(w.ctx)
	if err != nil {
		w.logger.Error("failed to obtain RuntimeVersion",
			"err", err,
			"runtime", w.runtimeID,
		)
	}

	// Add the key manager runtime to the node descriptor.  Done here instead
	// of in the registration's generic handler since the registration handler
	// only knows about normal runtimes.
	rtDesc := &node.Runtime{
		ID:        w.runtimeID,
		Version:   *rtVersion,
		ExtraInfo: cbor.Marshal(enclaveStatus),
	}
	rtDesc.Capabilities.TEE = tee
	n.Runtimes = append(n.Runtimes, rtDesc)

	n.AddRoles(node.RoleKeyManager)

	return nil
}

func (w *Worker) worker() {
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
	clientRuntimes := make(map[signature.MapKey]*clientRuntimeWatcher)
	clientRuntimesQuitCh := make(chan *clientRuntimeWatcher)
	defer close(clientRuntimesQuitCh)
	rtCh, rtSub := w.commonWorker.Registry.WatchRuntimes()
	defer rtSub.Close()

	var initialSyncDone bool
	for {
		select {
		case status := <-statusCh:
			if !status.ID.Equal(w.runtimeID) {
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

			// Forward status update to key manager runtime.
			if err := w.updateStatus(status); err != nil {
				w.logger.Error("failed to handle status update",
					"err", err,
				)
				continue
			}

			if !initialSyncDone {
				// Signal that we are initialized.
				close(w.initCh)
				initialSyncDone = true
			}
		case rt := <-rtCh:
			if rt.Kind != registry.KindCompute || !rt.KeyManager.Equal(w.runtimeID) {
				continue
			}
			if clientRuntimes[rt.ID.ToMapKey()] != nil {
				continue
			}

			w.logger.Info("seen new runtime using us as a key manager",
				"runtime_id", rt.ID,
			)

			node, err := w.commonWorker.NewUnmanagedCommitteeNode(rt.ID, false)
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

			clientRuntimes[rt.ID.ToMapKey()] = crw
		case crw := <-clientRuntimesQuitCh:
			w.logger.Error("client runtime watcher quit unexpectedly, terminating",
				"runtme_id", crw.node.RuntimeID,
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

// Guarded by CrossNode.
func (crw *clientRuntimeWatcher) HandleEpochTransitionLocked(snapshot *committeeCommon.EpochSnapshot) {
	// TODO: Update the key manager access control policy (#1900).
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
