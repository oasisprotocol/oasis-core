package sync

import (
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// StorageSyncProtocolID is a unique protocol identifier for the storage sync protocol.
const StorageSyncProtocolID = "storagesync"

// StorageSyncProtocolVersion is the supported version of the storage sync protocol.
var StorageSyncProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}

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
	MethodGetCheckpoints              = "GetCheckpoints"
	MaxGetCheckpointsResponseTime     = 5 * time.Second
	MaxGetCheckpointsParallelRequests = 5
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

// GetCheckpointChunkResponse is a respose to a GetCheckpointChunk request.
type GetCheckpointChunkResponse struct {
	Chunk []byte `json:"chunk,omitempty"`
}
