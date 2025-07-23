// Package checkpointsync defines wire protocol together with client/server
// implementations for the checkpoint sync protocol, used for runtime state sync.
package checkpointsync

import (
	"time"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// CheckpointSyncProtocolID is a unique protocol identifier for the checkpoint sync protocol.
const CheckpointSyncProtocolID = "checkpointsync"

// CheckpointSyncProtocolVersion is the supported version of the checkpoint sync protocol.
var CheckpointSyncProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}

// ProtocolID returns the runtime checkpoint sync protocol ID.
func ProtocolID(chainContext string, runtimeID common.Namespace) core.ProtocolID {
	return protocol.NewRuntimeProtocolID(chainContext, runtimeID, CheckpointSyncProtocolID, CheckpointSyncProtocolVersion)
}

// Constants related to the GetCheckpoints method.
const (
	MethodGetCheckpoints = "GetCheckpoints"
)

// GetCheckpointsRequest is a GetCheckpoints request.
type GetCheckpointsRequest struct {
	Version uint16 `json:"version"`
}

// GetCheckpointsResponse is a response to a GetCheckpoints request.
type GetCheckpointsResponse struct {
	Checkpoints []*checkpoint.Metadata `json:"checkpoints,omitempty"`
}

// Constants related to the GetCheckpointChunk method.
const (
	MethodGetCheckpointChunk          = "GetCheckpointChunk"
	MaxGetCheckpointChunkResponseTime = time.Minute
)

// GetCheckpointChunkRequest is a GetCheckpointChunk request.
type GetCheckpointChunkRequest struct {
	Version uint16    `json:"version"`
	Root    api.Root  `json:"root"`
	Index   uint64    `json:"index"`
	Digest  hash.Hash `json:"digest"`
}

// GetCheckpointChunkResponse is a response to a GetCheckpointChunk request.
type GetCheckpointChunkResponse struct {
	Chunk []byte `json:"chunk,omitempty"`
}

func init() {
	peermgmt.RegisterNodeHandler(&peermgmt.NodeHandlerBundle{
		ProtocolsFn: func(n *node.Node, chainContext string) []core.ProtocolID {
			if !n.HasRoles(node.RoleComputeWorker | node.RoleStorageRPC) {
				return []core.ProtocolID{}
			}

			protocols := make([]core.ProtocolID, len(n.Runtimes))
			for i, rt := range n.Runtimes {
				protocols[i] = protocol.NewRuntimeProtocolID(chainContext, rt.ID, CheckpointSyncProtocolID, CheckpointSyncProtocolVersion)
			}

			return protocols
		},
	})
}
