package committee

import (
	"github.com/oasislabs/ekiden/go/common/crash"
)

const (
	crashPointLeaderBatchPublishAfter  = "worker.compute.leader.batch.publish.after"
	crashPointBatchReceiveAfter        = "worker.compute.batch.receive.after"
	crashPointBatchProcessStartAfter   = "worker.compute.batch.process_start.after"
	crashPointBatchAbortAfter          = "worker.compute.batch.abort.after"
	crashPointBatchProposeBefore       = "worker.compute.batch.propose.before"
	crashPointBatchProposeAfter        = "worker.compute.batch.propose.after"
	crashPointDiscrepancyDetectedAfter = "worker.compute.batch.discrepancy_detected.after"
	crashPointRoothashReceiveAfter     = "worker.compute.batch.roothash.receive.after"
)

func init() {
	crash.RegisterCrashPoints(
		crashPointLeaderBatchPublishAfter,
		crashPointBatchReceiveAfter,
		crashPointBatchProcessStartAfter,
		crashPointBatchAbortAfter,
		crashPointBatchProposeBefore,
		crashPointBatchProposeAfter,
		crashPointDiscrepancyDetectedAfter,
		crashPointRoothashReceiveAfter,
	)
}
