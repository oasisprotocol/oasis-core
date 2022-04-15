package sync

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

// Client is a storage sync protocol client.
type Client interface {
	// GetDiff requests a write log of entries that must be applied to get from the first given root
	// to the second one.
	GetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, rpc.PeerFeedback, error)

	// GetCheckpoints returns a list of checkpoint metadata for all known checkpoints.
	GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Checkpoint, error)

	// GetCheckpointChunk requests a specific checkpoint chunk.
	GetCheckpointChunk(
		ctx context.Context,
		request *GetCheckpointChunkRequest,
		cp *Checkpoint,
	) (*GetCheckpointChunkResponse, rpc.PeerFeedback, error)
}

// Checkpoint contains checkpoint metadata together with peer information.
type Checkpoint struct {
	*checkpoint.Metadata

	// Peers are the feedback structures of all the peers that have advertised this checkpoint.
	Peers []rpc.PeerFeedback
}

type client struct {
	rcDiff        rpc.Client
	rcCheckpoints rpc.Client
}

func (c *client) GetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, rpc.PeerFeedback, error) {
	var rsp GetDiffResponse
	pf, err := c.rcDiff.Call(ctx, MethodGetDiff, request, &rsp, MaxGetDiffResponseTime)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Checkpoint, error) {
	var rsp GetCheckpointsResponse
	rsps, pfs, err := c.rcCheckpoints.CallMulti(ctx, MethodGetCheckpoints, request, rsp,
		MaxGetCheckpointsResponseTime,
		MaxGetCheckpointsParallelRequests,
	)
	if err != nil {
		return nil, err
	}

	// Combine deduplicated results into a single result.
	var checkpoints []*Checkpoint
	cps := make(map[hash.Hash]*Checkpoint)
	for i, peerRsp := range rsps {
		peerCps := peerRsp.(*GetCheckpointsResponse).Checkpoints

		for _, cpMeta := range peerCps {
			h := cpMeta.EncodedHash()
			cp := cps[h]
			if cp == nil {
				cp = &Checkpoint{
					Metadata: cpMeta,
				}
				cps[h] = cp
				checkpoints = append(checkpoints, cp)
			}
			cp.Peers = append(cp.Peers, pfs[i])
		}

		// Record success for a peer if it returned at least one checkpoint.
		if len(peerCps) > 0 {
			pfs[i].RecordSuccess()
		}
	}
	return checkpoints, nil
}

func (c *client) GetCheckpointChunk(
	ctx context.Context,
	request *GetCheckpointChunkRequest,
	cp *Checkpoint,
) (*GetCheckpointChunkResponse, rpc.PeerFeedback, error) {
	var opts []rpc.CallOption
	// When a checkpoint is passed, we limit requests to only those peers that actually advertised
	// having the checkpoint in question to avoid needless requests.
	if cp != nil {
		opts = append(opts, rpc.WithLimitPeers(cp.Peers))
	}

	var rsp GetCheckpointChunkResponse
	pf, err := c.rcCheckpoints.Call(ctx, MethodGetCheckpointChunk, request, &rsp,
		MaxGetCheckpointChunkResponseTime,
		opts...,
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new storage sync protocol client.
func NewClient(p2p rpc.P2P, runtimeID common.Namespace) Client {
	return &client{
		// Use two separate clients for the same protocol. This is to make sure that peers are
		// scored differently between the two use cases (syncing diffs vs. syncing checkpoints). We
		// could consider separating this into two protocols in the future.
		rcDiff:        rpc.NewClient(p2p, runtimeID, StorageSyncProtocolID, StorageSyncProtocolVersion),
		rcCheckpoints: rpc.NewClient(p2p, runtimeID, StorageSyncProtocolID, StorageSyncProtocolVersion),
	}
}
