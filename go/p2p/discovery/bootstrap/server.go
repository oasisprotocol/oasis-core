package bootstrap

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/p2p/discovery/peerstore"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

// service handles requests for service advertisement and peer discovery.
type service struct {
	logger *logging.Logger

	host  host.Host
	store *peerstore.Store

	allowPrivateIPs bool
}

// newSeedService creates a new seed node service.
func newSeedService(host host.Host, store *peerstore.Store, allowPrivateIPs bool) rpc.Service {
	return &service{
		host:            host,
		store:           store,
		allowPrivateIPs: allowPrivateIPs,
		logger:          logging.GetLogger("p2p/discovery/bootstrap"),
	}
}

// HandleRequest implements rpc.Service.
func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (any, error) {
	switch method {
	case MethodAdvertise:
		peerID, ok := rpc.PeerIDFromContext(ctx)
		if !ok {
			return nil, fmt.Errorf("failed to read peer ID from ctx")
		}

		var req AdvertiseRequest
		if err := cbor.Unmarshal(body, &req); err != nil {
			return nil, ErrBadRequest
		}

		return s.handleAdvertise(req.Namespace, peerID)

	case MethodDiscover:
		var req DiscoverRequest
		if err := cbor.Unmarshal(body, &req); err != nil {
			return nil, ErrBadRequest
		}

		return s.handleDiscovery(req.Namespace, req.Limit)
	}

	return nil, ErrMethodNotSupported
}

func (s *service) handleAdvertise(ns string, peerID core.PeerID) (*AdvertiseResponse, error) {
	addrs := s.host.Peerstore().Addrs(peerID)
	if !s.allowPrivateIPs {
		var pubAddrs []multiaddr.Multiaddr
		for _, addr := range addrs {
			if manet.IsPublicAddr(addr) {
				pubAddrs = append(pubAddrs, addr)
			}
		}
		addrs = pubAddrs
	}

	switch len(addrs) {
	case 0:
		ttl := s.store.Remove(ns, peerID)

		return &AdvertiseResponse{
			TTL: ttl,
		}, nil
	default:
		info := peer.AddrInfo{
			ID:    peerID,
			Addrs: addrs,
		}

		ttl, err := s.store.Add(ns, info)
		if err != nil {
			return nil, fmt.Errorf("failed to add peer to the store: %w", err)
		}

		return &AdvertiseResponse{
			TTL: ttl,
		}, nil
	}
}

func (s *service) handleDiscovery(ns string, limit int) (*DiscoverResponse, error) {
	if limit < 1 || limit > MaxPeers {
		limit = MaxPeers
	}

	peers := s.store.NamespacePeers(ns, limit)

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
func NewServer(host host.Host, store *peerstore.Store, allowPrivateIPs bool) rpc.Server {
	return rpc.NewServer(ProtocolID(), newSeedService(host, store, allowPrivateIPs))
}
