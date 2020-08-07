package committee

import (
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
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
		Actions: []accessctl.Action{},
	}
	// NOTE: GetDiff/GetCheckpoint* need to be accessible to all storage nodes,
	// not just the ones in the current storage committee so that new nodes can
	// sync-up.
	storageNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodGetDiff.FullName()),
			accessctl.Action(api.MethodGetCheckpoints.FullName()),
			accessctl.Action(api.MethodGetCheckpointChunk.FullName()),
		},
	}
	sentryNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodGetDiff.FullName()),
			accessctl.Action(api.MethodGetCheckpoints.FullName()),
			accessctl.Action(api.MethodGetCheckpointChunk.FullName()),
			accessctl.Action(api.MethodApply.FullName()),
			accessctl.Action(api.MethodApplyBatch.FullName()),
		},
	}
)
