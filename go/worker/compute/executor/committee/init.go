package committee

import (
	"github.com/oasisprotocol/oasis-core/go/common/crash"
)

const (
	crashPointBatchReceiveAfter        = "worker.executor.batch.receive.after"
	crashPointBatchProcessStartAfter   = "worker.executor.batch.process_start.after"
	crashPointBatchAbortAfter          = "worker.executor.batch.abort.after"
	crashPointBatchProposeBefore       = "worker.executor.batch.propose.before"
	crashPointBatchProposeAfter        = "worker.executor.batch.propose.after"
	crashPointDiscrepancyDetectedAfter = "worker.executor.batch.discrepancy_detected.after"
	crashPointRoothashReceiveAfter     = "worker.executor.batch.roothash.receive.after"
	crashPointBatchPublishAfter        = "worker.executor.batch.schedule.publish.after"
)

func init() {
	crash.RegisterCrashPoints(
		crashPointBatchReceiveAfter,
		crashPointBatchProcessStartAfter,
		crashPointBatchAbortAfter,
		crashPointBatchProposeBefore,
		crashPointBatchProposeAfter,
		crashPointDiscrepancyDetectedAfter,
		crashPointRoothashReceiveAfter,
		crashPointBatchPublishAfter,
	)
}
