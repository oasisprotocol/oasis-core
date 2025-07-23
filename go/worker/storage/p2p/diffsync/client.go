package diffsync

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
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
	rc  rpc.Client
	mgr rpc.PeerManager
}

func (c *client) GetDiff(ctx context.Context, request *GetDiffRequest) (*GetDiffResponse, rpc.PeerFeedback, error) {
	var rsp GetDiffResponse
	pf, err := c.rc.CallOne(ctx, c.mgr.GetBestPeers(), MethodGetDiff, request, &rsp,
		rpc.WithMaxPeerResponseTime(MaxGetDiffResponseTime),
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new diff sync protocol client.
//
// Moreover, it ensures underlying p2p service starts tracking protocol peers.
func NewClient(p2p rpc.P2P, chainContext string, runtimeID common.Namespace) Client {
	pid := protocol.NewRuntimeProtocolID(chainContext, runtimeID, DiffSyncProtocolID, DiffSyncProtocolVersion)
	rc := rpc.NewClient(p2p.Host(), pid)
	mgr := rpc.NewPeerManager(p2p, pid)
	rc.RegisterListener(mgr)

	p2p.RegisterProtocol(pid, minProtocolPeers, totalProtocolPeers)

	return &client{
		rc:  rc,
		mgr: mgr,
	}
}
