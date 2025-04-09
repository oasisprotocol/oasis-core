package bootstrap

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/p2p/discovery/peerstore"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

// service handles requests for service advertisement and peer discovery.
type service struct {
	logger *logging.Logger

	store *peerstore.Store
}

// newSeedService creates a new seed node service.
func newSeedService(s *peerstore.Store) rpc.Service {
	l := logging.GetLogger("p2p/discovery/bootstrap")

	srv := service{
		logger: l,
		store:  s,
	}

	return &srv
}

// HandleRequest implements rpc.Service.
func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (any, error) {
	switch method {
	case MethodAdvertise:
		addr, ok := rpc.PeerAddrInfoFromContext(ctx)
		if !ok {
			return nil, fmt.Errorf("failed to read peer's addr info from ctx")
		}

		var req AdvertiseRequest
		if err := cbor.Unmarshal(body, &req); err != nil {
			return nil, ErrBadRequest
		}

		return s.handleAdvertise(&req, addr)

	case MethodDiscover:
		var req DiscoverRequest
		if err := cbor.Unmarshal(body, &req); err != nil {
			return nil, ErrBadRequest
		}

		return s.handleDiscovery(&req)
	}

	return nil, ErrMethodNotSupported
}

func (s *service) handleAdvertise(req *AdvertiseRequest, info peer.AddrInfo) (*AdvertiseResponse, error) {
	ttl, err := s.store.Add(req.Namespace, info)
	if err != nil {
		return nil, fmt.Errorf("failed to add peer to the store: %w", err)
	}

	return &AdvertiseResponse{
		TTL: ttl,
	}, nil
}

func (s *service) handleDiscovery(req *DiscoverRequest) (*DiscoverResponse, error) {
	limit := MaxPeers
	if req.Limit > 0 && req.Limit < MaxPeers {
		limit = req.Limit
	}

	peers := s.store.NamespacePeers(req.Namespace, limit)

	jsons := make([][]byte, 0, len(peers))
	for _, info := range peers {
		json, err := info.MarshalJSON()
		if err != nil {
			return nil, err
		}
		jsons = append(jsons, json)
	}

	return &DiscoverResponse{
		Peers: jsons,
	}, nil
}

// NewServer creates a new bootstrap protocol server.
func NewServer(s *peerstore.Store) rpc.Server {
	return rpc.NewServer(ProtocolID(), newSeedService(s))
}
