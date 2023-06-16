package abci

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// maybeHaltForUpgrade will check whether the node needs to stop due to an upgrade being scheduled
// in the next consensus block and gracefully (e.g. without panicking) start the node halt process
// if this is indeed the case.
func (mux *abciMux) maybeHaltForUpgrade() {
	upgrader := mux.state.Upgrader()
	if upgrader == nil {
		return
	}

	// Determine the epoch that will become the current epoch in the next block.
	epoch, err := mux.state.GetCurrentEpoch(context.Background())
	if err != nil {
		mux.logger.Warn("failed to get current epoch",
			"err", err,
		)
		return
	}
	height := mux.state.BlockHeight()

	// Check if we need to halt for an upgrade -- but do not actually run the upgrade.
	switch err := upgrader.ConsensusUpgrade(nil, epoch, height); err {
	case nil:
		// Everything ok.
	case upgrade.ErrStopForUpgrade:
		// Signal graceful stop for upgrade.
		mux.haltForUpgrade(height, epoch, false)
		return
	default:
		mux.logger.Warn("error while trying to determine whether to upgrade",
			"err", err,
		)
	}

	// Also check local configuration for halt conditions.
	if mux.state.shouldLocalHalt(height, epoch) {
		mux.haltForUpgrade(height, epoch, false)
	}
}

func (mux *abciMux) haltForUpgrade(blockHeight int64, currentEpoch beacon.EpochTime, doPanic bool) {
	mux.haltOnce.Do(func() {
		mux.logger.Debug("dispatching halt hooks for upgrade")

		for _, hook := range mux.haltHooks {
			hook(mux.state.ctx, blockHeight, currentEpoch, upgrade.ErrStopForUpgrade)
		}

		mux.logger.Debug("halt hook dispatch complete")
	})

	// Trigger panic to signal the need to interrupt regular block processing.
	if doPanic {
		panic(upgrade.ErrStopForUpgrade)
	}
}

func (s *applicationState) shouldLocalHalt(blockHeight int64, currentEpoch beacon.EpochTime) bool {
	if s.haltHeight != 0 && uint64(blockHeight) >= s.haltHeight {
		return true
	} else if s.haltEpoch > 0 && s.haltEpoch != beacon.EpochInvalid && currentEpoch >= s.haltEpoch && currentEpoch != beacon.EpochInvalid {
		return true
	}
	return false
}
