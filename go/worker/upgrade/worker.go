package upgrade

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// Worker is a service handling governance upgrades.
type Worker struct { // nolint: maligned
	ctx context.Context

	upgrader upgrade.Backend

	consensus  consensus.Backend
	governance governance.Backend
	epochtime  epochtime.Backend

	stopCh chan struct{}
	quitCh chan struct{}

	logger *logging.Logger
}

func (w *Worker) doWatchGovernanceUpgrades() {
	defer close(w.quitCh)

	w.logger.Info("staring governance update worker")

	epochCh, sub := w.epochtime.WatchEpochs()
	defer sub.Close()

	// Wait for first block to be synced so that initial queries won't fail.
	func() {
		blkCh, blkSub, err := w.consensus.WatchBlocks(w.ctx)
		if err != nil {
			w.logger.Error("error watching consensus blocks",
				"err", err,
			)
			return
		}
		defer blkSub.Close()
		select {
		case <-w.ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-blkCh:
		}
	}()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-w.stopCh:
			return
		case currentEpoch := <-epochCh:
			w.logger.Debug("epoch transition event received",
				"epoch", currentEpoch,
			)
			// Query governance consensus parameters.
			params, err := w.governance.ConsensusParameters(w.ctx, consensus.HeightLatest)
			if err != nil {
				w.logger.Error("failed to query governance consensus parameters",
					"err", err,
				)
				return
			}
			// Query governance pending upgrades.
			govPendingUpgrades, err := w.governance.PendingUpgrades(w.ctx, consensus.HeightLatest)
			if err != nil {
				w.logger.Error("failed to query pending upgrades",
					"err", err,
				)
				return
			}
			w.logger.Debug("governance scheduled pending upgrades",
				"gov_pending_upgrades", govPendingUpgrades,
				"current_epoch", currentEpoch,
				"upgrade_cancel_min_epoch_diff", params.UpgradeCancelMinEpochDiff,
			)

			// Get pending upgrades that cannot be canceled anymore.
			// Note: we only submit upgrades that are past the cancel epoch,
			// to avoid having to potentially cancel upgrades.
			var govUpgradeDescriptors []*upgrade.Descriptor
			for _, descriptor := range govPendingUpgrades {
				if descriptor.Epoch-currentEpoch < params.UpgradeCancelMinEpochDiff {
					govUpgradeDescriptors = append(govUpgradeDescriptors, descriptor)
				}
			}
			// Get already scheduled upgrades on the node.
			var nodePendingUpgrades []*upgrade.PendingUpgrade
			nodePendingUpgrades, err = w.upgrader.PendingUpgrades(w.ctx)
			if err != nil {
				w.logger.Error("failed to query scheduled pending upgrades",
					"err", err,
				)
				return
			}
			w.logger.Debug("scheduled pending upgrades",
				"gov_pending_upgrades", govUpgradeDescriptors,
				"node_pending_upgrades", nodePendingUpgrades,
			)

			// Make sure all governance pending upgrades are scheduled.
			for _, descriptor := range govUpgradeDescriptors {
				w.logger.Debug("scheduling node upgrade",
					"descriptor", descriptor,
				)

				// Check if upgrade is already scheduled.
				var isScheduled bool
				for _, npu := range nodePendingUpgrades {
					if !npu.Descriptor.Equals(descriptor) {
						continue
					}
					// Upgrade already pending, skip submitting the descriptor.
					w.logger.Debug("governance upgrade already pending on the node",
						"descriptor", npu,
					)
					isScheduled = true
					break
				}
				if isScheduled {
					continue
				}

				// Submit governance scheduled node upgrade.
				w.logger.Debug("submitting governance update descriptor",
					"err", err,
				)
				if err = w.upgrader.SubmitDescriptor(w.ctx, descriptor); err != nil {
					w.logger.Error("failed to submit upgrade descriptor",
						"err", err,
					)
					return
				}
			}
		}
	}
}

// New constructs a new worker node upgrade service.
func New(
	consensus consensus.Backend,
	upgrader upgrade.Backend,
) (*Worker, error) {
	logger := logging.GetLogger("worker/upgrade")
	w := &Worker{
		ctx:        context.Background(),
		consensus:  consensus,
		governance: consensus.Governance(),
		epochtime:  consensus.EpochTime(),
		upgrader:   upgrader,
		stopCh:     make(chan struct{}),
		quitCh:     make(chan struct{}),
		logger:     logger,
	}

	return w, nil
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "worker node upgrade service"
}

// Start starts the registration service.
func (w *Worker) Start() error {
	w.logger.Info("starting node worker service")

	go w.doWatchGovernanceUpgrades()

	return nil
}

// Stop halts the service.
func (w *Worker) Stop() {
	close(w.stopCh)
}

// Quit returns a channel that will be closed when the service terminates.
func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (w *Worker) Cleanup() {
}
