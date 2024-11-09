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
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// Ensure that the runtime host notifier implements the Notifier interface.
var _ protocol.Notifier = (*runtimeHostNotifier)(nil)

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

// Implements protocol.Notifier.
func (n *runtimeHostNotifier) Start() {
	n.Lock()
	defer n.Unlock()

	if n.started {
		return
	}
	n.started = true

	go n.watchPolicyUpdates()
	go n.watchConsensusLightBlocks()
}

// Implements protocol.Notifier.
func (n *runtimeHostNotifier) Stop() {
	close(n.stopCh)
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
	stCh, stSub := n.consensus.KeyManager().Secrets().WatchStatuses()
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

	retryTicker := time.NewTicker(retryInterval)
	defer retryTicker.Stop()

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
			if err = n.updateKeyManagerStatus(ctx, st); err != nil {
				n.logger.Error("failed to update key manager status",
					"err", err,
				)
			} else {
				statusUpdated = true
			}
		}

		// Make sure that we actually have a new quote policy and that the current runtime version
		// supports quote policy updates.
		if !quotePolicyUpdated && sc != nil && sc.Policy != nil {
			if err = n.updateKeyManagerQuotePolicy(ctx, sc.Policy); err != nil {
				n.logger.Error("failed to update key manager quote policy",
					"err", err,
				)
			} else {
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
		case <-retryTicker.C:
			// Retry updates if some of them failed. When using CometBFT as a backend service
			// the host will see the new state one block before the consensus verifier as the former
			// sees the block H after it is executed while the latter needs to trust the block H
			// first by verifying the signatures which are only available after the block H+1
			// finalizes.
		}
	}
}

func (n *runtimeHostNotifier) updateKeyManagerStatus(ctx context.Context, status *secrets.Status) error {
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
