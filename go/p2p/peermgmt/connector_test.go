package peermgmt

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/conngater"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ConnectorTestSuite struct {
	suite.Suite

	host  host.Host
	gater *conngater.BasicConnectionGater

	peers []host.Host

	all     []peer.AddrInfo
	allowed []peer.AddrInfo
	blocked []peer.AddrInfo

	connector *peerConnector
}

func TestConnectorTestSuite(t *testing.T) {
	suite.Run(t, new(ConnectorTestSuite))
}

func (s *ConnectorTestSuite) SetupTest() {
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

	s.all = make([]peer.AddrInfo, 0, len(s.peers))
	for _, p := range s.peers {
		info := peer.AddrInfo{
			ID:    p.ID(),
			Addrs: p.Addrs(),
		}
		s.all = append(s.all, info)
	}

	// A gater which blocks first few peers.
	s.gater, err = conngater.NewBasicConnectionGater(nil)
	require.NoError(err, "NewBasicConnectionGater failed")

	b := 2
	s.blocked = s.all[:b]
	s.allowed = s.all[b:]

	for _, info := range s.blocked {
		err = s.gater.BlockPeer(info.ID)
		require.NoError(err, "BlockPeer failed")
	}

	// One connector to play with.
	s.connector = newPeerConnector(s.host, s.gater)
}

func (s *ConnectorTestSuite) TearDownTest() {
	require := require.New(s.T())

	for _, p := range s.peers {
		err := p.Close()
		require.NoError(err, "Peer Close failed")
	}

	err := s.host.Close()
	require.NoError(err, "Host Close failed")
}

func (s *ConnectorTestSuite) TestConnect() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s.Run("Blocked peer", func() {
		require := require.New(s.T())

		connected := s.connector.connect(ctx, s.blocked[0])
		require.False(connected)

		require.Equal(0, len(s.host.Network().Peers()))
	})

	s.Run("Empty address", func() {
		require := require.New(s.T())

		info := peer.AddrInfo{}
		connected := s.connector.connect(ctx, info)
		require.False(connected)

		require.Equal(0, len(s.host.Network().Peers()))
	})

	s.Run("Host not allowed", func() {
		require := require.New(s.T())

		info := peer.AddrInfo{
			ID:    s.host.ID(),
			Addrs: s.host.Addrs(),
		}
		connected := s.connector.connect(ctx, info)
		require.False(connected)

		require.Equal(0, len(s.host.Network().Peers()))
	})

	s.Run("Canceled context", func() {
		require := require.New(s.T())

		ctx2, cancel2 := context.WithCancel(ctx)
		cancel2()

		connected := s.connector.connect(ctx2, s.allowed[0])
		require.False(connected)

		require.Equal(0, len(s.host.Network().Peers()))
	})

	s.Run("Happy path", func() {
		require := require.New(s.T())

		connected := s.connector.connect(ctx, s.allowed[0])
		require.True(connected)

		require.Equal(1, len(s.host.Network().Peers()))
	})

	s.Run("DoS", func() {
		require := require.New(s.T())

		var wg sync.WaitGroup
		for range 100 {
			wg.Go(func() {
				connected := s.connector.connect(ctx, s.allowed[1])
				require.True(connected)
			})
		}
		wg.Wait()
		require.Equal(2, len(s.host.Network().Peers()))
	})
}

func (s *ConnectorTestSuite) TestConnectMany() {
	time.Sleep(time.Second)

	sendToCh := func(peers []peer.AddrInfo) <-chan peer.AddrInfo {
		peerCh := make(chan peer.AddrInfo, len(peers))
		for _, addr := range peers {
			peerCh <- addr
		}
		close(peerCh)
		return peerCh
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s.Run("No peers", func() {
		require := require.New(s.T())

		s.connector.connectMany(ctx, sendToCh(nil), 1000)
		require.Equal(0, len(s.host.Network().Peers()))

		s.connector.connectMany(ctx, sendToCh(s.allowed), -1)
		require.Equal(0, len(s.host.Network().Peers()))
	})

	s.Run("Canceled ctx", func() {
		require := require.New(s.T())

		ctx2, cancel2 := context.WithCancel(ctx)
		cancel2()

		s.connector.connectMany(ctx2, sendToCh(s.all), 1)
		require.Equal(0, len(s.host.Network().Peers()))
	})

	s.Run("Happy path - limited", func() {
		require := require.New(s.T())

		s.connector.connectMany(ctx, sendToCh(s.all), 2)
		require.Equal(2, len(s.host.Network().Peers()))
	})

	s.Run("Happy path - unlimited", func() {
		require := require.New(s.T())

		s.connector.connectMany(ctx, sendToCh(s.all), 100)
		require.Equal(len(s.allowed), len(s.host.Network().Peers()))
	})
}
