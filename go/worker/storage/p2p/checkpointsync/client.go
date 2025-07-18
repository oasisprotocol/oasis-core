package checkpointsync

import (
	"context"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/synclegacy"
)

const (
	// minProtocolPeers is the minimum number of peers from the registry we want to have connected
	// for checkpoint sync protocol.
	minProtocolPeers = 5

	// totalProtocolPeers is the number of peers we want to have connected for checkpoint sync protocol.
	totalProtocolPeers = 10
)

// Client is a checkpoint sync protocol client.
type Client interface {
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
	rc          rpc.Client
	mgr         rpc.PeerManager
	fallbackMgr rpc.PeerManager
}

func (c *client) GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Checkpoint, error) {
	var rsp GetCheckpointsResponse
	rsps, pfs, err := c.rc.CallMulti(ctx, c.getBestPeers(), MethodGetCheckpoints, request, rsp)
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
	peers := c.getBestPeers(opts...)
	pf, err := c.rc.CallOne(ctx, peers, MethodGetCheckpointChunk, request, &rsp,
		rpc.WithMaxPeerResponseTime(MaxGetCheckpointChunkResponseTime),
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) getBestPeers(opts ...rpc.BestPeersOption) []core.PeerID {
	return append(c.mgr.GetBestPeers(opts...), c.fallbackMgr.GetBestPeers(opts...)...)
}

// NewClient creates a new checkpoint sync protocol client.
//
// Previously, it was part of the storage sync protocol. To enable seamless rolling
// upgrades of the network, this client has a fallback to the old legacy protocol.
// The new protocol is prioritized.
//
// Warning: This client only registers the checkpoint sync protocol with the P2P
// service. To enable advertisement of the legacy protocol, it must be registered
// separately.
func NewClient(p2p rpc.P2P, chainContext string, runtimeID common.Namespace) Client {
	pid := protocol.NewRuntimeProtocolID(chainContext, runtimeID, CheckpointSyncProtocolID, CheckpointSyncProtocolVersion)
	fallbackPid := synclegacy.GetStorageSyncProtocolID(chainContext, runtimeID)
	rc := rpc.NewClient(p2p.Host(), pid, fallbackPid)
	mgr := rpc.NewPeerManager(p2p, pid)
	rc.RegisterListener(mgr)

	// Fallback protocol requires a separate manager to manage peers that also support legacy protocol.
	fallbackMgr := rpc.NewPeerManager(p2p, fallbackPid)
	rc.RegisterListener(fallbackMgr)

	p2p.RegisterProtocol(pid, minProtocolPeers, totalProtocolPeers)

	return &client{
		rc:          rc,
		mgr:         mgr,
		fallbackMgr: fallbackMgr,
	}
}
