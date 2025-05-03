package registry

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/eapache/channels"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

const (
	// notifyTimeout is the maximum time to wait for a notification to be processed by the runtime.
	notifyTimeout = 10 * time.Second

	// keyManagerUpdateRetryInterval is the time interval used between failed key manager updates.
	keyManagerUpdateRetryInterval = time.Second
	// maxKeyManagerUpdateRetries is the maximum number of key manager update retries.
	maxKeyManagerUpdateRetries = 16

	// minAttestationInterval is the minimum attestation interval.
	minAttestationInterval = 5 * time.Minute
)

// Ensure that the runtime host notifier implements the Notifier interface.
var _ protocol.Notifier = (*runtimeHostNotifier)(nil)

type componentNotifyFunc func(context.Context, host.RichRuntime)

// Queue names.
//
// Multiple queues are used so that notifications of a given kind do not block notifications of
// other kinds. All queues are created for each component independently.
const (
	queueKeyManagerStatus      = "key-manager/status"
	queueKeyManagerQuotePolicy = "key-manager/quote-policy"
	queueConsensusSync         = "consensus-sync"
)

const (
	// notifyMainQueueSize is the size of the main routing queue.
	notifyMainQueueSize = 64
	// notifyComponentQueueSize is the size of each per-component queue.
	//
	// If the queue would overflow, the oldest entry is overwritten.
	notifyComponentQueueSize = 1
)

type componentNotifyFuncWithQueue struct {
	queue string
	f     componentNotifyFunc
}

// runtimeHostNotifier is a runtime host notifier suitable for compute runtimes. It handles things
// like key manager policy updates.
type runtimeHostNotifier struct {
	startOne cmSync.One

	runtime   Runtime
	host      *composite.Host
	consensus consensus.Service

	notifyCh chan *componentNotifyFuncWithQueue

	logger *logging.Logger
}

// NewRuntimeHostNotifier returns a protocol notifier that handles key manager policy updates.
func NewRuntimeHostNotifier(runtime Runtime, host *composite.Host, consensus consensus.Service) protocol.Notifier {
	logger := logging.GetLogger("runtime/registry/notifier").With("runtime_id", runtime.ID())

	return &runtimeHostNotifier{
		startOne:  cmSync.NewOne(),
		runtime:   runtime,
		host:      host,
		consensus: consensus,
		notifyCh:  make(chan *componentNotifyFuncWithQueue, notifyMainQueueSize),
		logger:    logger,
	}
}

// Implements protocol.Notifier.
func (n *runtimeHostNotifier) Start() {
	n.startOne.TryStart(n.run)
}

// Implements protocol.Notifier.
func (n *runtimeHostNotifier) Stop() {
	n.startOne.TryStop()
}

func (n *runtimeHostNotifier) run(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		n.watchPolicyUpdates(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		n.watchConsensusLightBlocks(ctx)
	}()

	n.broadcastNotifications(ctx)
}

func (n *runtimeHostNotifier) notifyComponents(queue string, f componentNotifyFunc) {
	n.notifyCh <- &componentNotifyFuncWithQueue{
		queue: queue,
		f:     f,
	}
}

func (n *runtimeHostNotifier) broadcastNotifications(ctx context.Context) {
	type queueID struct {
		comp  component.ID
		queue string
	}
	type componentNotifier struct {
		cancelFn context.CancelFunc
		notifyCh *channels.RingChannel
	}
	queues := make(map[queueID]*componentNotifier)

	var wg sync.WaitGroup
	defer wg.Wait()

	runner := func(runnerCtx context.Context, qid queueID, notifyCh <-chan any) {
		defer wg.Done()

		n.logger.Debug("starting notification broadcast for component",
			"component_id", qid.comp,
			"queue", qid.queue,
		)
		defer func() {
			n.logger.Debug("notification broadcast for component terminating",
				"component_id", qid.comp,
				"queue", qid.queue,
			)
		}()

		for {
			select {
			case <-runnerCtx.Done():
				return
			case f, ok := <-notifyCh:
				if !ok {
					return
				}

				comp, ok := n.host.Component(qid.comp)
				if !ok {
					// Will be cleaned up by the manager loop.
					continue
				}

				rr := host.NewRichRuntime(comp)
				f.(componentNotifyFunc)(runnerCtx, rr)
			}
		}
	}

	n.logger.Debug("starting notification broadcast to components")

	defer func() {
		for _, cn := range queues {
			cn.cancelFn()
			cn.notifyCh.Close()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			n.logger.Debug("broadcast terminating")
			return
		case fq := <-n.notifyCh:
			// Dispatch to all components using a per-component queue to not block others.
			for compID := range n.host.Components() {
				qid := queueID{comp: compID, queue: fq.queue}
				notifier, ok := queues[qid]
				if !ok {
					runnerCtx, cancelFn := context.WithCancel(ctx)

					notifier = &componentNotifier{
						cancelFn: cancelFn,
						notifyCh: channels.NewRingChannel(channels.BufferCap(notifyComponentQueueSize)),
					}
					queues[qid] = notifier

					wg.Add(1)
					go runner(runnerCtx, qid, notifier.notifyCh.Out())
				}

				notifier.notifyCh.In() <- fq.f
			}
		}

		// Drop queues for any removed components.
		for qid, cn := range queues {
			if _, ok := n.host.Component(qid.comp); ok {
				continue
			}

			cn.cancelFn()
			cn.notifyCh.Close()
			delete(queues, qid)
		}
	}
}

func (n *runtimeHostNotifier) watchPolicyUpdates(ctx context.Context) {
	// Retrieve the key manager runtime ID from the consensus layer.
	keyManager := func() *common.Namespace {
		// Subscribe to runtime descriptor updates.
		dscCh, dscSub, err := n.runtime.WatchRegistryDescriptor()
		if err != nil {
			n.logger.Error("failed to subscribe to registry descriptor updates",
				"err", err,
			)
			return nil
		}
		defer dscSub.Close()

		// Obtain the current runtime descriptor.
		rtDsc, err := n.runtime.RegistryDescriptor(ctx)
		if err != nil {
			n.logger.Error("failed to get registry descriptor",
				"err", err,
			)
			return nil
		}

		// Only proceed with key manager policy updates for compute runtimes.
		if rtDsc.Kind != registry.KindCompute {
			n.logger.Debug("skipping watching policy updates for non-compute runtime")
			return nil
		}

		// Wait for the runtime to choose the key manager.
		for {
			if rtDsc.KeyManager != nil {
				return rtDsc.KeyManager
			}

			select {
			case <-ctx.Done():
				n.logger.Debug("context canceled")
				return nil
			case rtDsc = <-dscCh:
				n.logger.Debug("got registry descriptor update",
					"key_manager", rtDsc.KeyManager,
				)
			}
		}
	}()

	if keyManager != nil {
		n.watchKmPolicyUpdates(ctx, keyManager)
	}
}

func (n *runtimeHostNotifier) watchKmPolicyUpdates(ctx context.Context, kmRtID *common.Namespace) {
	// No need to watch anything if key manager is not set.
	if kmRtID == nil {
		return
	}

	n.logger.Debug("watching key manager policy updates", "keymanager", kmRtID)

	// Subscribe to key manager status updates (policy might change).
	stCh, stSub, err := n.consensus.KeyManager().Secrets().WatchStatuses(ctx)
	if err != nil {
		n.logger.Error("failed to watch key manager secrets statuses",
			"err", err,
		)
		return
	}
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
	evCh, evSub := n.host.WatchEvents()
	defer evSub.Close()

	var (
		statusUpdated      = true
		quotePolicyUpdated = true
	)

	var (
		st *secrets.Status
		sc *node.SGXConstraints
		vi *registry.VersionInfo
	)

	for {
		// Make sure that we actually have a new status.
		if !statusUpdated && st != nil {
			n.updateKeyManagerStatus(st)
			statusUpdated = true
		}

		// Make sure that we actually have a new quote policy and that the current runtime version
		// supports quote policy updates.
		if !quotePolicyUpdated && sc != nil && sc.Policy != nil {
			n.updateKeyManagerQuotePolicy(sc.Policy)
			quotePolicyUpdated = true
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
		}
	}
}

func (n *runtimeHostNotifier) updateKeyManagerStatus(status *secrets.Status) {
	n.logger.Debug("got key manager status update", "status", status)

	req := &protocol.Body{RuntimeKeyManagerStatusUpdateRequest: &protocol.RuntimeKeyManagerStatusUpdateRequest{
		Status: *status,
	}}

	n.notifyComponents(queueKeyManagerStatus, func(ctx context.Context, rr host.RichRuntime) {
		for range maxKeyManagerUpdateRetries {
			callCtx, cancelFn := context.WithTimeout(ctx, notifyTimeout)
			_, err := rr.Call(callCtx, req)
			cancelFn()

			if err != nil {
				n.logger.Error("failed dispatching key manager status update to runtime",
					"err", err,
				)
				select {
				case <-ctx.Done():
				case <-time.After(keyManagerUpdateRetryInterval):
					continue
				}
			}
			break
		}
	})
}

func (n *runtimeHostNotifier) updateKeyManagerQuotePolicy(policy *quote.Policy) {
	n.logger.Debug("got key manager quote policy update", "policy", policy)

	req := &protocol.Body{RuntimeKeyManagerQuotePolicyUpdateRequest: &protocol.RuntimeKeyManagerQuotePolicyUpdateRequest{
		Policy: *policy,
	}}

	n.notifyComponents(queueKeyManagerQuotePolicy, func(ctx context.Context, rr host.RichRuntime) {
		for range maxKeyManagerUpdateRetries {
			callCtx, cancelFn := context.WithTimeout(ctx, notifyTimeout)
			_, err := rr.Call(callCtx, req)
			cancelFn()

			if err != nil {
				n.logger.Error("failed dispatching key manager quote policy update to runtime",
					"err", err,
				)
				select {
				case <-ctx.Done():
				case <-time.After(keyManagerUpdateRetryInterval):
					continue
				}
			}
			break
		}
	})
}

func (n *runtimeHostNotifier) watchConsensusLightBlocks(ctx context.Context) {
	rawCh, sub, err := n.consensus.WatchBlocks(ctx)
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
		case <-ctx.Done():
			n.logger.Debug("context canceled")
			return
		case dsc := <-dscCh:
			// We only care about TEE-enabled runtimes.
			if dsc.TEEHardware != node.TEEHardwareIntelSGX {
				continue
			}

			var epoch beacon.EpochTime
			epoch, err = n.consensus.Beacon().GetEpoch(ctx, consensus.HeightLatest)
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
			params, err = n.consensus.Registry().ConsensusParameters(ctx, consensus.HeightLatest)
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
			n.notifyComponents(queueConsensusSync, func(ctx context.Context, rr host.RichRuntime) {
				callCtx, cancelFn := context.WithTimeout(ctx, notifyTimeout)
				defer cancelFn()

				if err := rr.ConsensusSync(callCtx, height); err != nil {
					n.logger.Error("failed to notify runtime of a new consensus layer block",
						"err", err,
						"height", height,
					)
				}
			})

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
