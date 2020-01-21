package keymanager

import (
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
)

// Only members of the current executor committee and other key manager nodes
// can make gRPC calls to the key manager.
// Note that everyone can make `get_public_key` calls, this check is done by
// the `keymanager/api/.mustAllowAccess` function.
var (
	executorCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.Service.MethodCallEnclave.FullName()),
		},
	}
	kmNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.Service.MethodCallEnclave.FullName()),
		},
	}
	sentryNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(api.Service.MethodCallEnclave.FullName()),
		},
	}
)
