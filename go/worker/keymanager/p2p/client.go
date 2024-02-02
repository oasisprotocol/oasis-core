package p2p

import (
	"context"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	// minProtocolPeers is the minimum number of peers from the registry we want to have connected
	// for KeyManager protocol.
	minProtocolPeers = 5

	// totalProtocolPeers is the number of peers we want to have connected for KeyManager protocol.
	totalProtocolPeers = 5
)

// Client is a keymanager protocol client.
type Client interface {
	// CallEnclave calls a key manager enclave with the provided data.
	//
	// The peer to which the call will be routed is chosen at random from the given list.
	CallEnclave(ctx context.Context, request *CallEnclaveRequest, peers []core.PeerID) (*CallEnclaveResponse, rpc.PeerFeedback, error)
}

type client struct {
	rc  rpc.Client
	mgr rpc.PeerManager
}

func (c *client) CallEnclave(ctx context.Context, request *CallEnclaveRequest, peers []core.PeerID) (*CallEnclaveResponse, rpc.PeerFeedback, error) {
	var rsp CallEnclaveResponse
	pf, err := c.rc.CallOne(ctx, c.mgr.GetBestPeers(rpc.WithLimitPeers(peers)), MethodCallEnclave, request, &rsp,
		rpc.WithMaxPeerResponseTime(MethodCallEnclaveTimeout),
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new keymanager protocol client.
func NewClient(p2p p2p.Service, chainContext string, keymanagerID common.Namespace) Client {
	pid := protocol.NewRuntimeProtocolID(chainContext, keymanagerID, KeyManagerProtocolID, KeyManagerProtocolVersion)
	mgr := rpc.NewPeerManager(p2p, pid)
	rc := rpc.NewClient(p2p.Host(), pid)
	rc.RegisterListener(mgr)

	p2p.RegisterProtocol(pid, minProtocolPeers, totalProtocolPeers)

	return &client{
		rc:  rc,
		mgr: mgr,
	}
}
