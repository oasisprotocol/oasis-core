package pub

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	// minProtocolPeers is the minimum number of peers from the registry we want to have connected
	// for StoragePub protocol.
	minProtocolPeers = 5

	// totalProtocolPeers is the number of peers we want to have connected for StoragePub protocol.
	totalProtocolPeers = 10
)

// Client is a storage pub protocol client.
type Client interface {
	// Get fetches a single key and returns the corresponding proof.
	Get(ctx context.Context, request *GetRequest) (*ProofResponse, rpc.PeerFeedback, error)

	// GetPrefixes fetches all keys under the given prefixes and returns the corresponding proofs.
	GetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, rpc.PeerFeedback, error)

	// Iterate seeks to a given key and then fetches the specified number of following items based
	// on key iteration order.
	Iterate(ctx context.Context, request *IterateRequest) (*ProofResponse, rpc.PeerFeedback, error)
}

type client struct {
	rc  rpc.Client
	mgr rpc.PeerManager
}

func (c *client) Get(ctx context.Context, request *GetRequest) (*ProofResponse, rpc.PeerFeedback, error) {
	var rsp ProofResponse
	pf, err := c.rc.CallOne(ctx, c.mgr.GetBestPeers(), MethodGet, request, &rsp)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) GetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, rpc.PeerFeedback, error) {
	var rsp ProofResponse
	pf, err := c.rc.CallOne(ctx, c.mgr.GetBestPeers(), MethodGetPrefixes, request, &rsp)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) Iterate(ctx context.Context, request *IterateRequest) (*ProofResponse, rpc.PeerFeedback, error) {
	var rsp ProofResponse
	pf, err := c.rc.CallOne(ctx, c.mgr.GetBestPeers(), MethodIterate, request, &rsp)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new storage pub protocol client.
func NewClient(p2p rpc.P2P, chainContext string, runtimeID common.Namespace) Client {
	pid := ProtocolID(chainContext, runtimeID)
	mgr := rpc.NewPeerManager(p2p, pid)
	rc := rpc.NewClient(p2p.Host(), pid)
	rc.RegisterListener(mgr)

	p2p.RegisterProtocol(pid, minProtocolPeers, totalProtocolPeers)

	return &client{
		rc:  rc,
		mgr: mgr,
	}
}
