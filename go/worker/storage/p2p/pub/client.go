package pub

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
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
	pf, err := c.rc.Call(ctx, c.mgr.GetBestPeers(), MethodGet, request, &rsp, MaxGetResponseTime)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) GetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, rpc.PeerFeedback, error) {
	var rsp ProofResponse
	pf, err := c.rc.Call(ctx, c.mgr.GetBestPeers(), MethodGetPrefixes, request, &rsp, MaxGetPrefixesResponseTime)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) Iterate(ctx context.Context, request *IterateRequest) (*ProofResponse, rpc.PeerFeedback, error) {
	var rsp ProofResponse
	pf, err := c.rc.Call(ctx, c.mgr.GetBestPeers(), MethodIterate, request, &rsp, MaxIterateResponseTime)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new storage pub protocol client.
func NewClient(p2p rpc.P2P, runtimeID common.Namespace) Client {
	pid := rpc.NewRuntimeProtocolID(runtimeID, StoragePubProtocolID, StoragePubProtocolVersion)
	mgr := rpc.NewPeerManager(p2p, pid)
	rc := rpc.NewClient(p2p.GetHost(), pid)
	rc.RegisterListener(mgr)

	return &client{
		rc:  rc,
		mgr: mgr,
	}
}
