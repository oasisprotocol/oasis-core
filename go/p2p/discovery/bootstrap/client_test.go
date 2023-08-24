package bootstrap

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/backup"
	"github.com/oasisprotocol/oasis-core/go/p2p/discovery/peerstore"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

type BootstrapTestSuite struct {
	suite.Suite

	seedHost  host.Host
	peerHosts []host.Host
	peers     []discovery.Discovery

	maliciousSeedHost host.Host
	maliciousPeerHost host.Host
	maliciousPeer     discovery.Discovery
}

func TestBootstrapTestSuite(t *testing.T) {
	suite.Run(t, new(BootstrapTestSuite))
}

func (s *BootstrapTestSuite) SetupSuite() {
	require := require.New(s.T())

	newHost := func() host.Host {
		signer, err := memory.NewFactory().Generate(signature.SignerP2P, rand.Reader)
		require.NoError(err, "Generate failed")

		listenAddr, err := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/0")
		require.NoError(err, "NewMultiaddr failed")

		host, err := libp2p.New(
			libp2p.ListenAddrs(listenAddr),
			libp2p.Identity(api.SignerToPrivKey(signer)),
		)
		require.NoError(err, "libp2p.New failed")

		return host
	}

	newSeed := func() rpc.Server {
		store := peerstore.NewStore(backup.NewInMemoryBackend())
		srv := NewServer(store)

		return srv
	}

	// Prepare a seed node.
	s.seedHost = newHost()
	seedSrv := newSeed()
	s.seedHost.SetStreamHandler(ProtocolID(), seedSrv.HandleStream)

	// Prepare seed address for the peers.
	ma := fmt.Sprintf("%s/p2p/%s", s.seedHost.Addrs()[0], s.seedHost.ID())
	seedAddr, err := peer.AddrInfoFromString(ma)
	require.NoError(err, "AddrInfoFromString failed")

	// Prepare few peers.
	numPeers := 10
	s.peerHosts = make([]host.Host, numPeers)
	s.peers = make([]discovery.Discovery, numPeers)
	for i := 0; i < numPeers; i++ {
		opts := []ClientOption{}
		if i > 0 {
			opts = append(opts, WithRetentionPeriod(time.Duration(0)))
		}
		s.peerHosts[i] = newHost()
		s.peers[i] = NewClient(s.peerHosts[i], *seedAddr, opts...)
	}

	// Prepare a malicious seed node.
	s.maliciousSeedHost = newHost()
	maliciousSrv := rpc.NewServer(ProtocolID(), s)
	s.maliciousSeedHost.SetStreamHandler(ProtocolID(), maliciousSrv.HandleStream)

	ma = fmt.Sprintf("%s/p2p/%s", s.maliciousSeedHost.Addrs()[0], s.maliciousSeedHost.ID())
	maliciousSeedAddr, err := peer.AddrInfoFromString(ma)
	require.NoError(err, "AddrInfoFromString failed")

	// Prepare a peer that communicates with malicious seed.
	s.maliciousPeerHost = newHost()
	s.maliciousPeer = NewClient(s.maliciousPeerHost, *maliciousSeedAddr, WithRetentionPeriod(time.Duration(0)))
}

func (s *BootstrapTestSuite) TearDownSuite() {
	// Stop everything.
	for _, h := range s.peerHosts {
		h.Close()
	}
	s.seedHost.Close()

	s.maliciousPeerHost.Close()
	s.maliciousSeedHost.Close()
}

func (s *BootstrapTestSuite) TestAdvertise() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s.Run("Empty namespace", func() {
		require := require.New(s.T())

		ttl, err := s.peers[0].Advertise(ctx, "")
		require.NoError(err, "Advertise failed")
		require.Equal(peerstore.PeerRegistrationTTL, ttl)
	})

	s.Run("One namespace", func() {
		require := require.New(s.T())

		ttl, err := s.peers[0].Advertise(ctx, "ns-0")
		require.NoError(err, "Advertise failed")
		require.Equal(peerstore.PeerRegistrationTTL, ttl)
	})

	s.Run("Repeat advertisements", func() {
		require := require.New(s.T())

		for i := 0; i < 5; i++ {
			ttl, err := s.peers[0].Advertise(ctx, "ns-1")
			require.NoError(err, "Advertise failed")
			require.Equal(peerstore.PeerRegistrationTTL, ttl)
		}
	})
}

func (s *BootstrapTestSuite) TestDiscovery() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	findPeers := func(d discovery.Discovery, ns string, limit int) int {
		peers, err := d.FindPeers(ctx, ns, discovery.Limit(limit))
		require.NoError(s.T(), err, "FindPeers failed")

		n := 0
		for range peers {
			n++
		}
		return n
	}

	s.Run("No peers", func() {
		require := require.New(s.T())

		require.Equal(0, findPeers(s.peers[0], "ns-404", 100))
	})

	s.Run("Many peers", func() {
		require := require.New(s.T())

		for _, peer := range s.peers {
			_, err := peer.Advertise(ctx, "ns-2")
			require.NoError(err, "Advertise failed")
		}
		require.Equal(len(s.peers), findPeers(s.peers[0], "ns-2", 100))
	})

	s.Run("Retention period", func() {
		require := require.New(s.T())

		n := 3

		// Advertise only first 3 peers.
		for _, peer := range s.peers[:n] {
			_, err := peer.Advertise(ctx, "ns-3")
			require.NoError(err, "Advertise failed")
		}

		require.Equal(n, findPeers(s.peers[0], "ns-3", 100))
		require.Equal(n, findPeers(s.peers[1], "ns-3", 100))

		// Advertise the rest. Note that peer 0 has retention period set and will return peers from
		// its cache.
		for _, peer := range s.peers[n:] {
			_, err := peer.Advertise(ctx, "ns-3")
			require.NoError(err, "Advertise failed")
		}

		require.Equal(n, findPeers(s.peers[0], "ns-3", 100))
		require.Equal(len(s.peers), findPeers(s.peers[1], "ns-3", 100))
		require.NotEqual(n, len(s.peers))
	})

	s.Run("Peer limit", func() {
		require := require.New(s.T())

		for _, peer := range s.peers {
			_, err := peer.Advertise(ctx, "ns-4")
			require.NoError(err, "Advertise failed")
		}
		require.Equal(1, findPeers(s.peers[1], "ns-4", 1))
		require.Equal(len(s.peers), findPeers(s.peers[1], "ns-4", 100))
	})

	s.Run("Malicious peer", func() {
		require := require.New(s.T())

		require.Equal(len(s.peers), findPeers(s.maliciousPeer, "limit", 100))

		// Should not return any peers as malicious seed will return more than 1 peer.
		require.Equal(0, findPeers(s.maliciousPeer, "limit", 1))

		// Should not return any peers as malicious seed will return 1 peer with invalid addr info.
		require.Equal(0, findPeers(s.maliciousPeer, "json", 100))
	})
}

// HandleRequest is a malicious seed which doesn't respect the protocol.
func (s *BootstrapTestSuite) HandleRequest(_ context.Context, _ string, body cbor.RawMessage) (interface{}, error) {
	var req DiscoverRequest
	if err := cbor.Unmarshal(body, &req); err != nil {
		return nil, ErrBadRequest
	}

	switch req.Namespace {
	case "limit":
		jsons := make([][]byte, 0, len(s.peers))
		for _, h := range s.peerHosts {
			addr := peer.AddrInfo{
				ID:    h.ID(),
				Addrs: h.Addrs(),
			}
			json, err := addr.MarshalJSON()
			if err != nil {
				return nil, err
			}
			jsons = append(jsons, json)
		}

		return &DiscoverResponse{
			Peers: jsons,
		}, nil

	case "json":
		return &DiscoverResponse{
			Peers: [][]byte{{1, 2, 3}},
		}, nil
	}

	return nil, nil
}
