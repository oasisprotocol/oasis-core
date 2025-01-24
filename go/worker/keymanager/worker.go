package keymanager

import (
	"context"
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
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
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

	nodeID signature.PublicKey

	runtime      runtimeRegistry.Runtime
	runtimeID    common.Namespace
	runtimeLabel string

	kmNodeWatcher    *kmNodeWatcher
	kmRuntimeWatcher *kmRuntimeWatcher
	secretsWorker    *secretsWorker
	churpWorker      *churpWorker

	accessControllers         []workerKeymanager.RPCAccessController
	accessControllersByMethod map[string]workerKeymanager.RPCAccessController

	peerMap    *PeerMap
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
			return ctrl.Connect(ctx, peerID)
		}
		if !slices.ContainsFunc(w.accessControllers, fn) {
			return nil, fmt.Errorf("not authorized to connect")
		}
	default:
		ctrl, ok := w.accessControllersByMethod[method]
		if !ok {
			return nil, fmt.Errorf("unsupported RPC method")
		}
		if err := ctrl.Authorize(ctx, method, kind, peerID); err != nil {
			return nil, fmt.Errorf("not authorized: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	req := &protocol.Body{
		RuntimeRPCCallRequest: &protocol.RuntimeRPCCallRequest{
			Request: data,
			Kind:    kind,
			PeerID:  []byte(peerID),
		},
	}

	rt := w.GetHostedRuntime()
	if rt == nil {
		return nil, fmt.Errorf("not initialized")
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

func (w *Worker) callEnclaveLocal(ctx context.Context, method string, args interface{}, rsp interface{}) error {
	rt := w.GetHostedRuntime()
	if rt == nil {
		return fmt.Errorf("not initialized")
	}
	return rt.LocalRPC(ctx, method, args, rsp)
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

// selectBlockHeight returns the height of a random block within the specified
// percentiles of the given epoch.
//
// Calculation is based on the current epoch and its block interval.
func (w *Worker) selectBlockHeight(epoch beacon.EpochTime, from uint8, to uint8) (int64, error) {
	// Fetch the height of the first block in the current epoch.
	now, err := w.commonWorker.Consensus.Beacon().GetEpoch(w.ctx, consensus.HeightLatest)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch epoch: %w", err)
	}
	first, err := w.commonWorker.Consensus.Beacon().GetEpochBlock(w.ctx, now)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch epoch block height: %w", err)
	}

	// Fetch the epoch interval for the current epoch.
	params, err := w.commonWorker.Consensus.Beacon().ConsensusParameters(w.ctx, consensus.HeightLatest)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	interval := params.Interval()

	// Use a zero interval when mocking epoch time, as the interval is untrusted.
	// It is set in genesis to a fixed value, but the real interval can vary
	// between epochs.
	if cmdFlags.DebugDontBlameOasis() && params.DebugMockBackend {
		interval = 0
	}

	// Pick a random block from the given percentile.
	offset := interval * int64(from) / 100
	span := interval * int64(to-from) / 100
	span = max(1, span)
	height := first + offset + rand.Int63n(span)

	// Estimate the block height for the given epoch.
	diff := int64(epoch) - int64(now)
	height = height + diff*interval

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

	// Key managers always need to use the enclave version given to them in the bundle
	// as they need to make sure that replication is possible during upgrades.
	var comp *bundle.ExplodedComponent
	if ok := func() bool {
		// Start watching runtime components so that we can wait for the runtime
		// to be discovered.
		bundleRegistry := w.commonWorker.RuntimeRegistry.GetBundleRegistry()
		compCh, compSub := bundleRegistry.WatchComponents(w.runtimeID)
		defer compSub.Close()

		// Make sure we have one version before proceeding.
		comps := bundleRegistry.Components(w.runtimeID)

		switch numComps := len(comps); numComps {
		case 0:
			w.logger.Info("waiting runtime component to be discovered")

			select {
			case comp = <-compCh:
			case <-w.ctx.Done():
				return false
			}
		case 1:
			comp = comps[0]
		default:
			w.logger.Error("expected a single runtime component (got %d)", numComps)
			return false
		}

		w.logger.Info("runtime component discovered",
			"id", comp.ID(),
			"version", comp.Version,
		)

		return true
	}(); !ok {
		return
	}
	if !comp.ID().IsRONL() {
		w.logger.Error("expected a RONL key manager runtime component (got %d)", comp.ID())
		return
	}

	// Provision the specified runtime component.
	w.logger.Info("provisioning key manager runtime component",
		"id", comp.ID(),
		"version", comp.Version,
	)

	if err := w.ProvisionHostedRuntimeComponent(comp); err != nil {
		w.logger.Error("failed to provision key manager runtime component",
			"err", err,
			"id", comp.ID(),
			"version", comp.Version,
		)
		return
	}

	// Set the runtime to the specified version.
	w.SetHostedRuntimeVersion(&comp.Version, nil)

	// Start the runtime and its notifier.
	hrt := w.GetHostedRuntime()
	hrtNotifier := w.GetRuntimeHostNotifier()

	hrtEventCh, hrtSub := hrt.WatchEvents()
	defer hrtSub.Close()

	hrt.Start()
	defer hrt.Stop()

	hrtNotifier.Start()
	defer hrtNotifier.Stop()

	// Ensure that the runtime version is active.
	if _, err := w.GetHostedRuntimeActiveVersion(); err != nil {
		w.logger.Error("failed to activate key manager runtime component",
			"err", err,
			"id", comp.ID(),
			"version", comp.Version,
		)
		return
	}

	// Always wait for the background watchers and workers to finish.
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(5)

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

	// Serve CHURP secrets.
	go func() {
		defer wg.Done()
		w.churpWorker.work(w.ctx, hrt)
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

	select {
	case <-w.churpWorker.Initialized():
	case <-w.ctx.Done():
		return
	}

	close(w.initCh)
}
