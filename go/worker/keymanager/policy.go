package keymanager

import (
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	enclaverpc "github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
)

// Only members of the current executor committee and other key manager nodes
// can make gRPC calls to the key manager.
//
// Note that everyone can make `get_public_key` calls, this check is done by
// the key manager EnclaveRPC endpoint registered in `go/keymanager/api/grpc.go`.
var (
	executorCommitteePolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(enclaverpc.MethodCallEnclave.FullName()),
		},
	}
	kmNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(enclaverpc.MethodCallEnclave.FullName()),
		},
	}
	sentryNodesPolicy = &committee.AccessPolicy{
		Actions: []accessctl.Action{
			accessctl.Action(enclaverpc.MethodCallEnclave.FullName()),
		},
	}
)
