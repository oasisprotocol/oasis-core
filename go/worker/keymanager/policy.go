package keymanager

import (
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
)

// Only members of the current compute committee and other key manager nodes
// can make gRPC calls to the key manager.
// Note that everyone can make `get_public_key` calls, as this is handled
// separately (in mustAllowAccess() in worker.go).
var (
	computeCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			"CallEnclave",
		},
	}
	kmNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			"CallEnclave",
		},
	}
)
