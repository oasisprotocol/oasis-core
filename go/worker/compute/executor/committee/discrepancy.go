package committee

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

type discrepancyEvent struct {
	rank   uint64
	height uint64
}

func (n *Node) NotifyDiscrepancy(info *discrepancyEvent) {
	// Drop discrepancies if the worker falls behind.
	select {
	case <-n.discrepancyCh:
	default:
	}

	// Non-blocking send.
	n.discrepancyCh <- info
}

func (n *Node) handleDiscrepancy(ctx context.Context, info *discrepancyEvent) {
	n.logger.Warn("execution discrepancy detected",
		"rank", info.rank,
		"height", info.height,
	)

	crash.Here(crashPointDiscrepancyDetectedAfter)

	discrepancyDetectedCount.With(n.getMetricLabels()).Inc()

	// Make sure that the runtime has synced this consensus block.
	err := n.rt.ConsensusSync(ctx, info.height)
	if err != nil {
		n.logger.Warn("failed to ask the runtime to sync the latest consensus block",
			"err", err,
			"height", info.height,
		)
	}
}

func (n *Node) handleObservedExecutorCommitment(ctx context.Context, ec *commitment.ExecutorCommitment) {
	n.logger.Debug("observed executor commitment",
		"commitment", ec,
	)

	// TODO: Handle equivocation detection.

	rt := n.epoch.GetRuntime()
	if err := commitment.VerifyExecutorCommitment(ctx, n.blockInfo.RuntimeBlock, rt, n.committee.ValidFor, ec, nil, n.epoch); err != nil {
		n.logger.Debug("ignoring bad observed executor commitment",
			"err", err,
			"node_id", ec.NodeID,
		)
		return
	}

	if err := n.commitPool.AddVerifiedExecutorCommitment(n.committee, ec); err != nil {
		n.logger.Debug("ignoring bad observed executor commitment",
			"err", err,
			"node_id", ec.NodeID,
		)
		return
	}

	// In case observed commits indicate a discrepancy, preempt consensus and immediately handle.
	if _, err := n.commitPool.ProcessCommitments(n.committee, rt.Executor.AllowedStragglers, false); err != commitment.ErrDiscrepancyDetected {
		return
	}

	n.logger.Warn("observed commitments indicate discrepancy")

	n.NotifyDiscrepancy(&discrepancyEvent{
		rank:   n.commitPool.HighestRank,
		height: uint64(n.blockInfo.ConsensusBlock.Height),
	})
}
