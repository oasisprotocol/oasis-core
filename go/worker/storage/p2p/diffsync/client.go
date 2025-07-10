package diffsync

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/synclegacy"
)

const (
	// minProtocolPeers is the minimum number of peers from the registry we want to have connected
	// for diff sync protocol.
	minProtocolPeers = 5

	// totalProtocolPeers is the number of peers we want to have connected for diff sync protocol.
	totalProtocolPeers = 10
)

// Client is a diff sync protocol client.
type Client interface {
	// GetDiff requests a write log of entries that must be applied to get from the first given root
	// to the second one.
	GetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, rpc.PeerFeedback, error)
}

type client struct {
	rc          rpc.Client
	mgr         rpc.PeerManager
	fallbackMgr rpc.PeerManager
}

func (c *client) GetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, rpc.PeerFeedback, error) {
	var rsp GetDiffResponse
	peers := append(c.mgr.GetBestPeers(), c.fallbackMgr.GetBestPeers()...)
	pf, err := c.rc.CallOne(ctx, peers, MethodGetDiff, request, &rsp,
		rpc.WithMaxPeerResponseTime(MaxGetDiffResponseTime),
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new diff sync protocol client.
//
// Previously, it was part of the storage sync protocol. To enable seamless rolling
// upgrades of the network, this client has a fallback to the old legacy protocol.
// The new protocol is prioritized.
//
// Warning: This client only registers the diff sync protocol with the P2P
// service. To enable advertisement of the legacy protocol, it must be registered
// separately.
func NewClient(p2p rpc.P2P, chainContext string, runtimeID common.Namespace) Client {
	pid := protocol.NewRuntimeProtocolID(chainContext, runtimeID, DiffSyncProtocolID, DiffSyncProtocolVersion)
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
