package peermgmt

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/conngater"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

type PeerManagerTestSuite struct {
	suite.Suite

	dir   string
	store *persistent.CommonStore

	host      host.Host
	peers     []host.Host
	infos     []*peer.AddrInfo
	protocols []core.ProtocolID

	manager *PeerManager
}

func TestPeerManagerTestSuite(t *testing.T) {
	suite.Run(t, new(PeerManagerTestSuite))
}

func (s *PeerManagerTestSuite) SetupTest() {
	require := require.New(s.T())

	// One host.
	var err error
	s.host, err = newTestHost()
	require.NoError(err, "newTestHost failed")

	// Few peers.
	n := 10
	s.peers = make([]host.Host, n)
	for i := 0; i < n; i++ {
		s.peers[i], err = newTestHost()
		require.NoError(err, "newTestHost failed")
	}

	s.infos = make([]*peer.AddrInfo, 0, len(s.peers))
	for _, p := range s.peers {
		info := peer.AddrInfo{
			ID:    p.ID(),
			Addrs: p.Addrs(),
		}
		s.infos = append(s.infos, &info)
	}

	// Prepare few protocols.
	s.protocols = make([]core.ProtocolID, 0, len(s.peers))
	for i := 0; i < n; i++ {
		s.protocols = append(s.protocols, core.ProtocolID(fmt.Sprintf("/protocol/%d.0.0", i)))
	}

	// Let every peer support few protocols.
	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			s.peers[i].SetStreamHandler(s.protocols[j], func(_ network.Stream) {})
		}
	}

	// Few stuff for the manager.
	gater, err := conngater.NewBasicConnectionGater(nil)
	require.NoError(err, "NewBasicConnectionGater failed")

	s.dir, err = os.MkdirTemp("", "oasis-p2p-peer-manager-test_")
	require.NoError(err, "TempDir failed")

	pubsub, err := pubsub.NewGossipSub(context.Background(), s.host)
	require.NoError(err, "NewGossipSub failed")

	s.store, err = persistent.NewCommonStore(s.dir)
	require.NoError(err, "NewCommonStore failed")

	// One manager to play with.
	s.manager = NewPeerManager(s.host, gater, pubsub, s.store)
}

func (s *PeerManagerTestSuite) TearDownTest() {
	require := require.New(s.T())

	for _, p := range s.peers {
		err := p.Close()
		require.NoError(err, "Peer Close failed")
	}

	err := s.host.Close()
	require.NoError(err, "Host Close failed")

	if s.dir != "" {
		os.RemoveAll(s.dir)
	}
}

func (s *PeerManagerTestSuite) TestStartStop() {
	s.Run("Stops", func() {
		s.manager.Start()
		s.manager.Stop()
	})
}

func (s *PeerManagerTestSuite) TestRegisterProtocol() {
	require := require.New(s.T())

	for i := 0; i < 3; i++ {
		p := core.ProtocolID(fmt.Sprintf("/protocol/test/%d.0.0", i))
		s.manager.RegisterProtocol(p, 1, 10)
		require.Equal(i+1, len(s.manager.Protocols()))
	}
}

func (s *PeerManagerTestSuite) TestRegisterTopic() {
	require := require.New(s.T())

	for i := 0; i < 3; i++ {
		t := fmt.Sprintf("topic %d", i)
		s.manager.RegisterTopic(t, 1, 10)
		require.Equal(i+1, len(s.manager.Topics()))
	}
}

func (s *PeerManagerTestSuite) TestUnregisterProtocol() {
	require := require.New(s.T())

	for i := 0; i < 3; i++ {
		p := core.ProtocolID(fmt.Sprintf("/protocol/test/%d.0.0", i))
		s.manager.RegisterProtocol(p, 1, 10)
		require.Equal(i+1, len(s.manager.Protocols()))
	}

	s.manager.UnregisterProtocol("404")
	require.Equal(3, len(s.manager.Protocols()))

	for i := 0; i < 3; i++ {
		p := core.ProtocolID(fmt.Sprintf("/protocol/test/%d.0.0", i))
		s.manager.UnregisterProtocol(p)
		require.Equal(2-i, len(s.manager.Protocols()))
	}

	s.manager.UnregisterProtocol("404")
	require.Equal(0, len(s.manager.Protocols()))
}

func (s *PeerManagerTestSuite) TestUnregisterTopic() {
	require := require.New(s.T())

	for i := 0; i < 3; i++ {
		t := fmt.Sprintf("topic %d", i)
		s.manager.RegisterTopic(t, 1, 10)
		require.Equal(i+1, len(s.manager.Topics()))
	}

	s.manager.UnregisterTopic("404")
	require.Equal(3, len(s.manager.Topics()))

	for i := 0; i < 3; i++ {
		s.manager.UnregisterTopic(fmt.Sprintf("topic %d", i))
		require.Equal(2-i, len(s.manager.Topics()))
	}

	s.manager.UnregisterTopic("404")
	require.Equal(0, len(s.manager.Topics()))
}

func (s *PeerManagerTestSuite) TestProtocolTracking() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s.Run("One peer", func() {
		require := require.New(s.T())

		err := s.host.Connect(ctx, *s.infos[0])
		require.NoError(err, "Connect failed")
		require.Equal(1, s.manager.NumProtocolPeers(s.protocols[0]))

		err = s.host.Network().ClosePeer(s.infos[0].ID)
		require.NoError(err, "ClosePeer failed")
		require.Equal(0, s.manager.NumProtocolPeers(s.protocols[0]))
	})

	s.Run("Many peers", func() {
		require := require.New(s.T())

		for _, info := range s.infos {
			err := s.host.Connect(ctx, *info)
			require.NoError(err, "Connect failed")
		}
		for i, p := range s.protocols {
			require.Equal(i+1, s.manager.NumProtocolPeers(p))
		}
	})

	s.Run("Disconnect few peers", func() {
		require := require.New(s.T())

		n := len(s.infos) / 2
		for _, info := range s.infos[:n] {
			err := s.host.Network().ClosePeer(info.ID)
			require.NoError(err, "ClosePeer failed")
		}
		for i, p := range s.protocols {
			exp := 0
			if i >= n {
				exp = i + 1 - n
			}
			require.Equal(exp, s.manager.NumProtocolPeers(p))
		}
	})
}

func newTestHost() (host.Host, error) {
	listenAddr, err := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/0")
	if err != nil {
		return nil, err
	}

	signer, err := memory.NewFactory().Generate(signature.SignerP2P, rand.Reader)
	if err != nil {
		return nil, err
	}

	return libp2p.New(
		libp2p.ListenAddrs(listenAddr),
		libp2p.Identity(api.SignerToPrivKey(signer)),
	)
}
