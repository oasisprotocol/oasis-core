package committee

import (
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

func (n *Node) handleDiscrepancyLocked(height uint64) {
	n.logger.Warn("execution discrepancy detected")

	crash.Here(crashPointDiscrepancyDetectedAfter)

	discrepancyDetectedCount.With(n.getMetricLabels()).Inc()

	// If the node is not a backup worker in this epoch, no need to do anything. Also if the
	// node is an executor worker in this epoch, then it has already processed and submitted
	// a commitment, so no need to do anything.
	epoch := n.commonNode.Group.GetEpochSnapshot()
	if !epoch.IsExecutorBackupWorker() || epoch.IsExecutorWorker() {
		return
	}

	// Make sure that the runtime has synced this consensus block.
	if rt := n.commonNode.GetHostedRuntime(); rt != nil {
		err := rt.ConsensusSync(n.roundCtx, height)
		if err != nil {
			n.logger.Warn("failed to ask the runtime to sync the latest consensus block",
				"err", err,
				"height", height,
			)
		}
	}

	var state StateWaitingForEvent
	switch s := n.state.(type) {
	case StateWaitingForBatch:
		// Discrepancy detected event received before the batch. We need to remember that there was
		// a discrepancy and keep waiting for the batch.
		s.discrepancyDetected = true
		n.transitionLocked(s)
		return
	case StateWaitingForEvent:
		state = s
	default:
		n.logger.Warn("ignoring received discrepancy event in incorrect state",
			"state", s,
		)
		return
	}

	// Backup worker, start processing a batch.
	n.logger.Info("backup worker activating and processing batch")
	n.startProcessingBatchLocked(state.batch)
}

// HandleNewEventLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewEventLocked(ev *roothash.Event) {
	switch {
	case ev.ExecutionDiscrepancyDetected != nil:
		n.handleDiscrepancyLocked(uint64(ev.Height))
	}
}

func (n *Node) handleObservedExecutorCommitment(ec *commitment.ExecutorCommitment) {
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	// Don't do anything if we are not a backup worker or we are an executor worker.
	es := n.commonNode.Group.GetEpochSnapshot()
	if !es.IsExecutorBackupWorker() || es.IsExecutorWorker() {
		return
	}

	n.logger.Debug("observed executor commitment",
		"commitment", ec,
	)

	// Make sure the executor commitment is for the next round.
	currentRound := n.commonNode.CurrentBlock.Header.Round
	nextRound := currentRound + 1
	if ec.Header.Header.Round != nextRound {
		n.logger.Debug("observed executor commitment is not for the next round",
			"ec_round", ec.Header.Header.Round,
			"next_round", nextRound,
		)
		return
	}

	// Initialize the pool if needed.
	if n.commitPool.Round != currentRound {
		n.commitPool.Runtime = es.GetRuntime()
		n.commitPool.Committee = es.GetExecutorCommittee().Committee
		n.commitPool.ResetCommitments(currentRound)
	}

	// TODO: Handle equivocation detection.

	err := n.commitPool.AddExecutorCommitment(n.ctx, n.commonNode.CurrentBlock, es, ec, nil)
	if err != nil {
		n.logger.Debug("ignoring bad observed executor commitment",
			"err", err,
			"node_id", ec.NodeID,
		)
		return
	}

	// In case observed commits indicate a discrepancy, preempt consensus and immediately handle.
	if _, err = n.commitPool.ProcessCommitments(false); err == commitment.ErrDiscrepancyDetected {
		n.logger.Warn("observed commitments indicate discrepancy")

		n.handleDiscrepancyLocked(uint64(n.commonNode.CurrentBlockHeight))
	}
}
