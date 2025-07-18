// Package diffsync defines wire protocol together with client/server
// implementations for the diff sync protocol, used for runtime block sync.
package diffsync

import (
	"time"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
)

// DiffSyncProtocolID is a unique protocol identifier for the diff sync protocol.
const DiffSyncProtocolID = "diffsync"

// DiffSyncProtocolVersion is the supported version of the diff sync protocol.
var DiffSyncProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}

// Constants related to the GetDiff method.
const (
	MethodGetDiff          = "GetDiff"
	MaxGetDiffResponseTime = 15 * time.Second
)

// GetDiffRequest is a GetDiff request.
type GetDiffRequest struct {
	StartRoot api.Root `json:"start_root"`
	EndRoot   api.Root `json:"end_root"`
}

// GetDiffResponse is a response to a GetDiff request.
type GetDiffResponse struct {
	WriteLog api.WriteLog `json:"write_log,omitempty"`
}

func init() {
	peermgmt.RegisterNodeHandler(&peermgmt.NodeHandlerBundle{
		ProtocolsFn: func(n *node.Node, chainContext string) []core.ProtocolID {
			if !n.HasRoles(node.RoleComputeWorker | node.RoleStorageRPC) {
				return []core.ProtocolID{}
			}

			protocols := make([]core.ProtocolID, len(n.Runtimes))
			for i, rt := range n.Runtimes {
				protocols[i] = protocol.NewRuntimeProtocolID(chainContext, rt.ID, DiffSyncProtocolID, DiffSyncProtocolVersion)
			}

			return protocols
		},
	})
}
