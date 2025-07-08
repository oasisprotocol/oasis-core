package registry

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/eapache/channels"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
)

const (
	// minAttestationInterval is the minimum attestation interval.
	minAttestationInterval = 5 * time.Minute
)

// LightBlockNotifier notifies runtimes about new light blocks and periodically
// triggers re-attestation.
type LightBlockNotifier struct {
	host     *composite.Host
	notifier *RuntimeHostNotifier

	runtime   Runtime
	consensus consensus.Service

	logger *logging.Logger
}

// NewLightBlockNotifier creates a new light block notifier.
func NewLightBlockNotifier(runtime Runtime, host *composite.Host, consensus consensus.Service, notifier *RuntimeHostNotifier) *LightBlockNotifier {
	logger := logging.GetLogger("runtime/notifier/light_blocks").
		With("runtime_id", runtime.ID())

	return &LightBlockNotifier{
		host:      host,
		notifier:  notifier,
		runtime:   runtime,
		consensus: consensus,
		logger:    logger,
	}
}

// Name returns the name of the notifier.
func (n *LightBlockNotifier) Name() string {
	return "light block notifier"
}

// Serve starts the notifier.
func (n *LightBlockNotifier) Serve(ctx context.Context) error {
	n.logger.Info("starting")
	defer n.logger.Info("stopping")

	rawCh, sub, err := n.consensus.Core().WatchBlocks(ctx)
	if err != nil {
		n.logger.Error("failed to subscribe to consensus block updates",
			"err", err,
		)
		return err
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
		return err
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
			return err
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
				return fmt.Errorf("block channel closed")
			}
			blk := rawBlk.(*consensus.Block)
			height := uint64(blk.Height)

			// Notify the runtime that a new consensus layer block is available.
			notify := func(ctx context.Context, rr host.RichRuntime) {
				callCtx, cancelFn := context.WithTimeout(ctx, notifyTimeout)
				defer cancelFn()

				if err := rr.ConsensusSync(callCtx, height); err != nil {
					n.logger.Error("failed to notify runtime of a new consensus layer block",
						"err", err,
						"height", height,
					)
				}
			}

			for compID := range n.host.Components() {
				nf := &Notification{
					comp:   compID,
					queue:  queueConsensusSync,
					notify: notify,
				}

				if err := n.notifier.Queue(nf); err != nil {
					n.logger.Error("failed to queue notification",
						"err", err,
						"height", height,
						"component_id", compID,
					)
				}
			}

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
