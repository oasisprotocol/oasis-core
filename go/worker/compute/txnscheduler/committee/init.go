package committee

import (
	"github.com/oasisprotocol/oasis-core/go/common/crash"
)

const (
	crashPointLeaderBatchPublishAfter = "worker.txnscheduler.leader.batch.publish.after"
)

func init() {
	crash.RegisterCrashPoints(
		crashPointLeaderBatchPublishAfter,
	)
}
