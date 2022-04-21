package committee

import (
	"context"

	"github.com/cenkalti/backoff/v4"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
)

// startRuntimeTrustSyncLocked asks the runtime to start syncing its light client up to the current
// latest height. If the runtime does not actually use a trust root, this will be a no-op.
//
// When syncing is completed, the runtimeTrustSycned flag will be set.
func (n *Node) startRuntimeTrustSyncLocked(rt host.RichRuntime) {
	n.cancelRuntimeTrustSyncLocked() // Cancel any outstanding sync.

	var ctx context.Context
	ctx, n.runtimeTrustSyncCncl = context.WithCancel(n.ctx)

	syncOp := func() error {
		blk, err := n.commonNode.Consensus.GetBlock(ctx, consensus.HeightLatest)
		if err != nil {
			n.logger.Warn("failed to retrieve consensus block for runtiem light client sync",
				"err", err,
			)
			return err
		}

		err = rt.ConsensusSync(ctx, uint64(blk.Height))
		if err != nil {
			n.logger.Warn("runtime failed to sync its light client",
				"err", err,
				"height", blk.Height,
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
		n.commonNode.CrossNode.Lock()
		defer n.commonNode.CrossNode.Unlock()

		n.runtimeTrustSynced = true
		n.nudgeAvailabilityLocked(true)
	}()
}

func (n *Node) cancelRuntimeTrustSyncLocked() {
	if n.runtimeTrustSyncCncl == nil {
		return
	}
	n.runtimeTrustSyncCncl()
	n.runtimeTrustSyncCncl = nil
}
