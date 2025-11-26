package committee

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

type discrepancyEvent struct {
	height        uint64
	round         uint64
	rank          uint64
	timeout       bool
	authoritative bool
}

func (n *Node) handleDiscrepancy(ctx context.Context, ev *discrepancyEvent) {
	if ev.round != n.blockInfo.RuntimeBlock.Header.Round+1 {
		n.logger.Debug("ignoring bad discrepancy event",
			"height", ev.height,
			"round", ev.round,
			"rank", ev.rank,
			"timeout", ev.timeout,
			"authoritative", ev.authoritative,
		)
		return
	}

	n.logger.Warn("execution discrepancy detected",
		"height", ev.height,
		"round", ev.round,
		"rank", ev.rank,
		"timeout", ev.timeout,
		"authoritative", ev.authoritative,
	)

	crash.Here(crashPointDiscrepancyDetectedAfter)

	discrepancyDetectedCount.With(n.getMetricLabels()).Inc()

	// Make sure that the runtime has synced this consensus block.
	err := n.rt.ConsensusSync(ctx, ev.height)
	if err != nil {
		n.logger.Warn("failed to ask the runtime to sync the latest consensus block",
			"err", err,
			"height", ev.height,
		)
	}

	// Always prioritize authoritative discrepancy events because they originate
	// from the consensus layer, are final, and limited to at most one per round.
	// Non-authoritative events, on the other hand, are merely estimates used
	// by the backup workers.
	if n.discrepancy != nil && n.discrepancy.authoritative {
		return
	}

	n.discrepancy = ev
}

func (n *Node) predictDiscrepancy(ctx context.Context, ec *commitment.ExecutorCommitment) {
	// TODO: Handle equivocation detection.

	// Don't do anything if the discrepancy has already been detected.
	if n.commitPool.Discrepancy {
		n.logger.Debug("ignoring bad observed executor commitment, discrepancy already detected",
			"node_id", ec.NodeID,
		)
		return
	}

	// Verify and add the commitment.
	if err := commitment.VerifyExecutorCommitment(ctx, n.blockInfo.RuntimeBlock, n.blockInfo.ActiveDescriptor, n.committee.ValidFor, ec, nil, n.epoch); err != nil {
		n.logger.Debug("ignoring bad observed executor commitment, verification failed",
			"err", err,
			"node_id", ec.NodeID,
		)
		return
	}

	if err := n.commitPool.AddVerifiedExecutorCommitment(n.committee, ec); err != nil {
		n.logger.Debug("ignoring bad observed executor commitment, insertion failed",
			"err", err,
			"node_id", ec.NodeID,
		)
		return
	}

	// In case observed commits indicate a discrepancy, preempt consensus and immediately handle.
	if _, err := n.commitPool.ProcessCommitments(n.committee, n.blockInfo.ActiveDescriptor.Executor.AllowedStragglers, false); err != commitment.ErrDiscrepancyDetected {
		return
	}

	n.logger.Warn("observed commitments indicate discrepancy")

	n.handleDiscrepancy(ctx, &discrepancyEvent{
		height:        uint64(n.blockInfo.ConsensusBlock.Height),
		round:         n.blockInfo.RuntimeBlock.Header.Round + 1,
		rank:          n.commitPool.HighestRank,
		timeout:       false,
		authoritative: false,
	})
}
