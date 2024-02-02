package keymanager

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"slices"
	"sync"
	"time"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	workerKeymanager "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	rpcCallTimeout = 2 * time.Second
)

// Ensure the key manager worker implements the BackgroundService interface.
var _ service.BackgroundService = (*Worker)(nil)

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
	quitCh    chan struct{}
	initCh    chan struct{}

	runtime      runtimeRegistry.Runtime
	runtimeID    common.Namespace
	runtimeLabel string

	kmNodeWatcher    *kmNodeWatcher
	kmRuntimeWatcher *kmRuntimeWatcher
	secretsWorker    *secretsWorker

	accessControllers         []workerKeymanager.RPCAccessController
	accessControllersByMethod map[string]workerKeymanager.RPCAccessController

	accessList *AccessList

	commonWorker *workerCommon.Worker
	roleProvider registration.RoleProvider
	backend      api.Backend

	enabled bool
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

	go w.worker()

	return nil
}

func (w *Worker) Stop() {
	w.logger.Info("stopping key manager worker")

	if !w.enabled {
		close(w.quitCh)
		return
	}

	// Stop the sub-components.
	w.cancelCtx()
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

func (w *Worker) CallEnclave(ctx context.Context, data []byte, kind enclaverpc.Kind) ([]byte, error) {
	// Peek into the frame/request data to extract the method.
	var method string
	switch kind {
	case enclaverpc.KindNoiseSession:
		var frame enclaverpc.Frame
		if err := cbor.Unmarshal(data, &frame); err != nil {
			return nil, fmt.Errorf("malformed RPC frame")
		}
		// Note that the untrusted plaintext is also checked in the enclave, so if the node lied
		// about what method it's using, we will know and the request will get rejected.
		method = frame.UntrustedPlaintext
	case enclaverpc.KindInsecureQuery:
		var req enclaverpc.Request
		if err := cbor.Unmarshal(data, &req); err != nil {
			return nil, fmt.Errorf("malformed RPC request")
		}
		method = req.Method
	default:
		// Local queries are not allowed.
		return nil, fmt.Errorf("unsupported RPC kind")
	}

	// Handle access control.
	peerID, ok := rpc.PeerIDFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("not authorized: unknown peer")
	}

	switch {
	case method == api.RPCMethodConnect && kind == enclaverpc.KindNoiseSession:
		// Allow connection if at least one controller grants authorization.
		fn := func(ctrl workerKeymanager.RPCAccessController) bool {
			return ctrl.Connect(peerID)
		}
		if !slices.ContainsFunc(w.accessControllers, fn) {
			return nil, fmt.Errorf("not authorized to connect")
		}
	default:
		ctrl, ok := w.accessControllersByMethod[method]
		if !ok {
			return nil, fmt.Errorf("unsupported RPC method")
		}
		if err := ctrl.Authorize(method, kind, peerID); err != nil {
			return nil, fmt.Errorf("not authorized: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	req := &protocol.Body{
		RuntimeRPCCallRequest: &protocol.RuntimeRPCCallRequest{
			Request: data,
			Kind:    kind,
		},
	}

	rt := w.GetHostedRuntime()
	if rt == nil {
		return nil, fmt.Errorf("not initialized")
	}
	rtInfo, err := rt.GetInfo(ctx)
	if err != nil {
		w.logger.Error("failed to fetch runtime features",
			"err", err,
		)
		return nil, fmt.Errorf("not initialized")
	}

	// Only include PeerIDs if the runtime supports it.
	if rtInfo.Features.RPCPeerID {
		req.RuntimeRPCCallRequest.PeerID = []byte(peerID)
	}

	response, err := rt.Call(ctx, req)
	if err != nil {
		w.logger.Error("failed to dispatch RPC call to runtime",
			"err", err,
			"kind", kind,
		)
		return nil, err
	}

	resp := response.RuntimeRPCCallResponse
	if resp == nil {
		w.logger.Error("malformed response from runtime",
			"response", response,
		)
		return nil, fmt.Errorf("malformed response from runtime")
	}

	return resp.Response, nil
}

func (w *Worker) callEnclaveLocal(method string, args interface{}, rsp interface{}) error {
	req := enclaverpc.Request{
		Method: method,
		Args:   args,
	}
	body := &protocol.Body{
		RuntimeLocalRPCCallRequest: &protocol.RuntimeLocalRPCCallRequest{
			Request: cbor.Marshal(&req),
		},
	}

	rt := w.GetHostedRuntime()
	if rt == nil {
		return fmt.Errorf("not initialized")
	}
	response, err := rt.Call(w.ctx, body)
	if err != nil {
		w.logger.Error("failed to dispatch local RPC call to runtime",
			"method", method,
			"err", err,
		)
		return err
	}

	resp := response.RuntimeLocalRPCCallResponse
	if resp == nil {
		w.logger.Error("malformed response from runtime",
			"method", method,
			"response", response,
		)
		return fmt.Errorf("malformed response from runtime")
	}

	var msg enclaverpc.Message
	if err = cbor.Unmarshal(resp.Response, &msg); err != nil {
		return fmt.Errorf("malformed message envelope: %w", err)
	}

	if msg.Response == nil {
		return fmt.Errorf("message is not a response: '%s'", hex.EncodeToString(resp.Response))
	}

	switch {
	case msg.Response.Body.Success != nil:
	case msg.Response.Body.Error != nil:
		return fmt.Errorf("rpc failure: '%s'", *msg.Response.Body.Error)
	default:
		return fmt.Errorf("unknown rpc response status: '%s'", hex.EncodeToString(resp.Response))
	}

	if err = cbor.Unmarshal(msg.Response.Body.Success, rsp); err != nil {
		return fmt.Errorf("failed to extract rpc response payload: %w", err)
	}

	return nil
}

func (w *Worker) runtimeAttestationKey() (*signature.PublicKey, error) {
	kmRt, err := w.runtime.RegistryDescriptor(w.ctx)
	if err != nil {
		return nil, err
	}

	var rak *signature.PublicKey
	switch kmRt.TEEHardware {
	case node.TEEHardwareInvalid:
		rak = &api.InsecureRAK
	case node.TEEHardwareIntelSGX:
		capabilityTEE, err := w.GetHostedRuntimeCapabilityTEE()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch TEE capability: %w", err)
		}
		if capabilityTEE == nil {
			return nil, fmt.Errorf("runtime is not running inside a TEE")
		}
		rak = &capabilityTEE.RAK
	default:
		return nil, fmt.Errorf("TEE hardware mismatch")
	}

	return rak, nil
}

func (w *Worker) runtimeEncryptionKeys(nodes []signature.PublicKey) (map[x25519.PublicKey]struct{}, error) {
	kmRt, err := w.runtime.RegistryDescriptor(w.ctx)
	if err != nil {
		return nil, err
	}

	reks := make(map[x25519.PublicKey]struct{})
	for _, id := range nodes {
		var n *node.Node
		n, err := w.commonWorker.Consensus.Registry().GetNode(w.ctx, &registry.IDQuery{
			Height: consensus.HeightLatest,
			ID:     id,
		})
		switch err {
		case nil:
		case registry.ErrNoSuchNode:
			continue
		default:
			return nil, err
		}

		idx := slices.IndexFunc(n.Runtimes, func(rt *node.Runtime) bool {
			// Skipping version check as key managers are running exactly one
			// version of the runtime.
			return rt.ID.Equal(&w.runtimeID)
		})
		if idx == -1 {
			continue
		}
		nRt := n.Runtimes[idx]

		var rek x25519.PublicKey
		switch kmRt.TEEHardware {
		case node.TEEHardwareInvalid:
			rek = api.InsecureREK
		case node.TEEHardwareIntelSGX:
			if nRt.Capabilities.TEE == nil || nRt.Capabilities.TEE.REK == nil {
				continue
			}
			rek = *nRt.Capabilities.TEE.REK
		default:
			continue
		}

		reks[rek] = struct{}{}
	}

	return reks, nil
}

// randomBlockHeight returns the height of a random block in the k-th percentile of the given epoch.
func (w *Worker) randomBlockHeight(epoch beacon.EpochTime, percentile int64) (int64, error) {
	// Get height of the first block.
	params, err := w.commonWorker.Consensus.Beacon().ConsensusParameters(w.ctx, consensus.HeightLatest)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	first, err := w.commonWorker.Consensus.Beacon().GetEpochBlock(w.ctx, epoch)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch epoch block height: %w", err)
	}

	// Pick a random height from the given percentile.
	interval := params.Interval()
	if percentile < 100 {
		interval = interval * percentile / 100
	}
	if interval <= 0 {
		interval = 1
	}
	height := first + rand.Int63n(interval)

	return height, nil
}

func (w *Worker) handleRuntimeHostEvent(ev *host.Event) {
	switch {
	case ev.Started != nil, ev.Updated != nil:
		var (
			version       version.Version
			capabilityTEE *node.CapabilityTEE
		)
		switch {
		case ev.Started != nil:
			version = ev.Started.Version
			capabilityTEE = ev.Started.CapabilityTEE
		case ev.Updated != nil:
			version = ev.Updated.Version
			capabilityTEE = ev.Updated.CapabilityTEE
		default:
			return
		}

		w.roleProvider.SetAvailableWithCallback(func(n *node.Node) error {
			rt := n.AddOrUpdateRuntime(w.runtime.ID(), version)
			rt.Version = version
			rt.Capabilities.TEE = capabilityTEE
			return nil
		}, func(context.Context) error {
			w.logger.Info("key manager registered",
				"version", version,
				"tee", capabilityTEE,
			)
			return nil
		})
	case ev.FailedToStart != nil, ev.Stopped != nil:
		// We can no longer service requests.
		w.roleProvider.SetUnavailable()
	default:
		// Unknown event.
		w.logger.Warn("unknown runtime host event",
			"ev", ev,
		)
	}
}

func (w *Worker) worker() {
	w.logger.Info("starting key manager worker")

	defer close(w.quitCh)

	// Wait for consensus sync.
	w.logger.Info("waiting consensus to finish initial synchronization")
	select {
	case <-w.ctx.Done():
		return
	case <-w.commonWorker.Consensus.Synced():
	}
	w.logger.Info("consensus has finished initial synchronization")

	// Provision the hosted runtime.
	w.logger.Info("provisioning key manager runtime")

	hrt, hrtNotifier, err := w.ProvisionHostedRuntime(w.ctx)
	if err != nil {
		w.logger.Error("failed to provision key manager runtime",
			"err", err,
		)
		return
	}

	hrtEventCh, hrtSub := hrt.WatchEvents()
	defer hrtSub.Close()

	hrt.Start()
	defer hrt.Stop()

	hrtNotifier.Start()
	defer hrtNotifier.Stop()

	// Key managers always need to use the enclave version given to them in the bundle
	// as they need to make sure that replication is possible during upgrades.
	activeVersion := w.runtime.HostVersions()[0] // Init made sure we have exactly one.
	if err = w.SetHostedRuntimeVersion(activeVersion, nil); err != nil {
		w.logger.Error("failed to activate key manager runtime version",
			"err", err,
			"version", activeVersion,
		)
		return
	}

	// Always wait for the background watchers and workers to finish.
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(4)

	// Need to explicitly watch for updates related to the key manager runtime
	// itself.
	go func() {
		defer wg.Done()
		w.kmNodeWatcher.watch(w.ctx)
	}()

	// Watch runtime registrations in order to know which runtimes are using
	// us as a key manager.
	go func() {
		defer wg.Done()
		w.kmRuntimeWatcher.watch(w.ctx)
	}()

	// Serve master and ephemeral secrets.
	go func() {
		defer wg.Done()
		w.secretsWorker.work(w.ctx, hrt)
	}()

	// Watch runtime updates and register with new capabilities on restarts.
	go func() {
		defer wg.Done()

		for {
			select {
			case ev := <-hrtEventCh:
				w.handleRuntimeHostEvent(ev)
			case <-w.ctx.Done():
				return
			}
		}
	}()

	// Wait for all workers to initialize.
	select {
	case <-w.secretsWorker.Initialized():
	case <-w.ctx.Done():
		return
	}

	close(w.initCh)
}
