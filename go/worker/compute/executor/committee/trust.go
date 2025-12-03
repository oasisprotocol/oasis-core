package committee

import (
	"context"

	"github.com/cenkalti/backoff/v4"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
)

// startRuntimeTrustSync asks the runtime to start syncing its light client up to the current
// latest height. If the runtime does not actually use a trust root, this will be a no-op.
//
// When syncing is completed, the runtimeTrustSycned flag will be set.
func (n *Node) startRuntimeTrustSyncLocked(rt host.RichRuntime) {
	n.cancelRuntimeTrustSyncLocked() // Cancel any outstanding sync.

	var ctx context.Context
	ctx, n.runtimeTrustSyncCancel = context.WithCancel(n.ctx)

	syncOp := func() error {
		height, err := n.commonNode.Consensus.Core().GetLatestHeight(ctx)
		if err != nil {
			n.logger.Warn("failed to retrieve latest consensus block height for runtime light client sync",
				"err", err,
			)
			return err
		}

		err = rt.ConsensusSync(ctx, uint64(height))
		if err != nil {
			n.logger.Warn("runtime failed to sync its light client",
				"err", err,
				"height", height,
			)
		}
		return err
	}

	go func() {
		n.logger.Info("asking the runtime to perform light client sync")

		boff := cmnBackoff.NewExponentialBackOff()
		err := backoff.Retry(syncOp, backoff.WithContext(boff, ctx))
		if err != nil {
			n.logger.Error("runtime light client sync failed",
				"err", err,
			)
			return
		}

		n.logger.Info("runtime light client sync succeeded")

		// Runtime has successfully synced its light client.
		n.mu.Lock()
		defer n.mu.Unlock()

		n.runtimeTrustSynced = true
		n.nudgeAvailabilityLocked(true)
	}()
}

func (n *Node) cancelRuntimeTrustSyncLocked() {
	if n.runtimeTrustSyncCancel == nil {
		return
	}
	n.runtimeTrustSyncCancel()
	n.runtimeTrustSyncCancel = nil
}
