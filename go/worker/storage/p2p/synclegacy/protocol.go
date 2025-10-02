// Package synclegacy defines wire protocol together with client/server
// implementations for the legacy storage sync protocol, used for runtime block sync.
//
// The protocol was split into storage diff and checkpoints protocol.
//
// TODO: Remove it: https://github.com/oasisprotocol/oasis-core/issues/6261
package synclegacy

import (
	"time"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// StorageSyncProtocolID is a unique protocol identifier for the storage sync protocol.
const StorageSyncProtocolID = "storagesync"

// StorageSyncProtocolVersion is the supported version of the storage sync protocol.
var StorageSyncProtocolVersion = version.Version{Major: 2, Minor: 0, Patch: 0}

// ProtocolID returns the runtime storage sync protocol ID.
func ProtocolID(chainContext string, runtimeID common.Namespace) core.ProtocolID {
	return protocol.NewRuntimeProtocolID(chainContext, runtimeID, StorageSyncProtocolID, StorageSyncProtocolVersion)
}

// Constants related to the GetDiff method.
const (
	MethodGetDiff          = "GetDiff"
	MaxGetDiffResponseTime = 15 * time.Second
)

// GetDiffRequest is a GetDiff request.
type GetDiffRequest struct {
	StartRoot storage.Root `json:"start_root"`
	EndRoot   storage.Root `json:"end_root"`
}

// GetDiffResponse is a response to a GetDiff request.
type GetDiffResponse struct {
	WriteLog storage.WriteLog `json:"write_log,omitempty"`
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
	MaxGetCheckpointChunkResponseTime = 60 * time.Second
)

// GetCheckpointChunkRequest is a GetCheckpointChunk request.
type GetCheckpointChunkRequest struct {
	Version uint16       `json:"version"`
	Root    storage.Root `json:"root"`
	Index   uint64       `json:"index"`
	Digest  hash.Hash    `json:"digest"`
}

// GetCheckpointChunkResponse is a response to a GetCheckpointChunk request.
type GetCheckpointChunkResponse struct {
	Chunk []byte `json:"chunk,omitempty"`
}

func init() {
	peermgmt.RegisterNodeHandler(&peermgmt.NodeHandlerBundle{
		ProtocolsFn: func(n *node.Node, chainContext string) []core.ProtocolID {
			if !n.HasRoles(node.RoleComputeWorker | node.RoleObserver | node.RoleStorageRPC) {
				return []core.ProtocolID{}
			}

			protocols := make([]core.ProtocolID, len(n.Runtimes))
			for i, rt := range n.Runtimes {
				protocols[i] = ProtocolID(chainContext, rt.ID)
			}

			return protocols
		},
	})
}
