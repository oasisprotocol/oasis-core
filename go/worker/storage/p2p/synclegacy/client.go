package synclegacy

import (
	"context"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

const (
	// minProtocolPeers is the minimum number of peers from the registry we want to have connected
	// for StorageSync protocol.
	minProtocolPeers = 5

	// totalProtocolPeers is the number of peers we want to have connected for StorageSync protocol.
	totalProtocolPeers = 10
)

// Client is a storage sync protocol client.
type Client interface {
	// GetDiff requests a write log of entries that must be applied to get from the first given root
	// to the second one.
	//
	// The request times out in [MaxGetDiffResponseTime].
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
	rcC  rpc.Client
	rcD  rpc.Client
	mgrC rpc.PeerManager
	mgrD rpc.PeerManager
}

func (c *client) GetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, rpc.PeerFeedback, error) {
	var rsp GetDiffResponse
	pf, err := c.rcD.CallOne(ctx, c.mgrD.GetBestPeers(), MethodGetDiff, request, &rsp,
		rpc.WithMaxPeerResponseTime(MaxGetDiffResponseTime),
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Checkpoint, error) {
	var rsp GetCheckpointsResponse
	rsps, pfs, err := c.rcC.CallMulti(ctx, c.mgrC.GetBestPeers(), MethodGetCheckpoints, request, rsp)
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
	var opts []rpc.BestPeersOption
	// When a checkpoint is passed, we limit requests to only those peers that actually advertised
	// having the checkpoint in question to avoid needless requests.
	if cp != nil {
		peers := make([]core.PeerID, 0, len(cp.Peers))
		for _, pf := range cp.Peers {
			peers = append(peers, pf.PeerID())
		}
		opts = append(opts, rpc.WithLimitPeers(peers))
	}

	var rsp GetCheckpointChunkResponse
	pf, err := c.rcC.CallOne(ctx, c.mgrC.GetBestPeers(opts...), MethodGetCheckpointChunk, request, &rsp,
		rpc.WithMaxPeerResponseTime(MaxGetCheckpointChunkResponseTime),
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new storage sync protocol client.
func NewClient(p2p rpc.P2P, chainContext string, runtimeID common.Namespace) Client {
	// Use two separate clients and managers for the same protocol. This is to make sure that peers
	// are scored differently between the two use cases (syncing diffs vs. syncing checkpoints). We
	// could consider separating this into two protocols in the future.
	pid := ProtocolID(chainContext, runtimeID)

	rcC := rpc.NewClient(p2p.Host(), pid)
	mgrC := rpc.NewPeerManager(p2p, pid)
	rcC.RegisterListener(mgrC)

	rcD := rpc.NewClient(p2p.Host(), pid)
	mgrD := rpc.NewPeerManager(p2p, pid)
	rcD.RegisterListener(mgrD)

	p2p.RegisterProtocol(pid, minProtocolPeers, totalProtocolPeers)

	return &client{
		rcC:  rcC,
		rcD:  rcD,
		mgrC: mgrC,
		mgrD: mgrD,
	}
}
