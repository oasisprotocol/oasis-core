package committee

import (
	"github.com/oasislabs/ekiden/go/common/accessctl"
	"github.com/oasislabs/ekiden/go/worker/common/committee"
)

// Define storage access policies for all the relevant committees and node
// groups.
var (
	computeCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			"Apply",
			"ApplyBatch",
		},
	}
	txnSchedulerCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			"Apply",
			"ApplyBatch",
		},
	}
	mergeCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			"Merge",
			"MergeBatch",
		},
	}
	// NOTE: GetDiff/GetCheckpoint need to be accessible to all storage nodes,
	// not just the ones in the current storage committee so that new nodes can
	// sync-up.
	storageNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			"GetDiff",
			"GetCheckpoint",
		},
	}
)
