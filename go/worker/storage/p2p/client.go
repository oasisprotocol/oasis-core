package p2p

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

// Client is a storage sync protocol client.
type Client interface {
	// GetDiff requests a write log of entries that must be applied to get from the first given root
	// to the second one.
	GetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, rpc.PeerFeedback, error)

	// GetCheckpoints returns a list of checkpoint metadata for all known checkpoints.
	GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) (*GetCheckpointsResponse, error)

	// GetCheckpointChunk requests a specific checkpoint chunk.
	GetCheckpointChunk(ctx context.Context, request *GetCheckpointChunkRequest) (*GetCheckpointChunkResponse, rpc.PeerFeedback, error)
}

type client struct {
	rc rpc.Client
}

func (c *client) GetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, rpc.PeerFeedback, error) {
	var rsp GetDiffResponse
	pf, err := c.rc.Call(ctx, MethodGetDiff, request, &rsp, MaxGetDiffResponseTime)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) (*GetCheckpointsResponse, error) {
	var rsp GetCheckpointsResponse
	rsps, pfs, err := c.rc.CallMulti(ctx, MethodGetCheckpoints, request, rsp, MaxGetCheckpointsResponseTime, MaxGetCheckpointsParallelRequests)
	if err != nil {
		return nil, err
	}

	// Combine deduplicated results into a single result.
	rsp.Checkpoints = nil
	cps := make(map[hash.Hash]bool)
	for i, peerRsp := range rsps {
		for _, cp := range peerRsp.(*GetCheckpointsResponse).Checkpoints {
			h := cp.EncodedHash()
			if cps[h] {
				continue
			}
			cps[h] = true
			rsp.Checkpoints = append(rsp.Checkpoints, cp)
		}

		// Record success for a peer.
		pfs[i].RecordSuccess()
	}
	return &rsp, nil
}

func (c *client) GetCheckpointChunk(ctx context.Context, request *GetCheckpointChunkRequest) (*GetCheckpointChunkResponse, rpc.PeerFeedback, error) {
	var rsp GetCheckpointChunkResponse
	pf, err := c.rc.Call(ctx, MethodGetCheckpointChunk, request, &rsp, MaxGetCheckpointChunkResponseTime)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new storage sync protocol client.
func NewClient(p2p rpc.P2P, runtimeID common.Namespace) Client {
	return &client{
		rc: rpc.NewClient(p2p, runtimeID, StorageSyncProtocolID, StorageSyncProtocolVersion),
	}
}
