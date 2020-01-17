package committee

import (
	"github.com/oasislabs/oasis-core/go/common/crash"
)

const (
	crashPointLeaderBatchPublishAfter = "worker.txnscheduler.leader.batch.publish.after"
)

func init() {
	crash.RegisterCrashPoints(
		crashPointLeaderBatchPublishAfter,
	)
}
