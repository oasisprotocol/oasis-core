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
			accessctl.Action(api.MethodSyncGet.FullName()),
			accessctl.Action(api.MethodSyncGetPrefixes.FullName()),
			accessctl.Action(api.MethodSyncIterate.FullName()),
			accessctl.Action(api.MethodApply.FullName()),
			accessctl.Action(api.MethodApplyBatch.FullName()),
		},
	}
	// NOTE: GetDiff/GetCheckpoint* need to be accessible to all storage nodes,
	// not just the ones in the current storage committee so that new nodes can
	// sync-up.
	storageNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodSyncGet.FullName()),
			accessctl.Action(api.MethodSyncGetPrefixes.FullName()),
			accessctl.Action(api.MethodSyncIterate.FullName()),
		},
	}
	sentryNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.MethodSyncGet.FullName()),
			accessctl.Action(api.MethodSyncGetPrefixes.FullName()),
			accessctl.Action(api.MethodSyncIterate.FullName()),
			accessctl.Action(api.MethodApply.FullName()),
			accessctl.Action(api.MethodApplyBatch.FullName()),
		},
	}
)
