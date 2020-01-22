package committee

import (
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
)

// Define storage access policies for all the relevant committees and node
// groups.
var (
	executorCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodApply.FullName()),
			accessctl.Action(api.MethodApplyBatch.FullName()),
		},
	}
	txnSchedulerCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodApply.FullName()),
			accessctl.Action(api.MethodApplyBatch.FullName()),
		},
	}
	mergeCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodMerge.FullName()),
			accessctl.Action(api.MethodMergeBatch.FullName()),
		},
	}
	// NOTE: GetDiff/GetCheckpoint need to be accessible to all storage nodes,
	// not just the ones in the current storage committee so that new nodes can
	// sync-up.
	storageNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodGetDiff.FullName()),
			accessctl.Action(api.MethodGetCheckpoint.FullName()),
		},
	}
	sentryNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodGetDiff.FullName()),
			accessctl.Action(api.MethodApply.FullName()),
			accessctl.Action(api.MethodApplyBatch.FullName()),
			accessctl.Action(api.MethodMerge.FullName()),
			accessctl.Action(api.MethodMergeBatch.FullName()),
		},
	}
)
