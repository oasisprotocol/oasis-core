package rpc

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

const (
	testMethod   = "test"
	testProtocol = core.ProtocolID("p2p/rpc/test/1.0.0")
)

type testRequest struct{}

type testResponse struct {
	ID int
}

type testService struct {
	id int
}

func (s *testService) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (interface{}, error) {
	if method != testMethod {
		return nil, fmt.Errorf("unsupported method")
	}
	var req testRequest
	if err := cbor.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if s.id < 2 {
		return nil, fmt.Errorf("first two servers are corrupted")
	}
	return &testResponse{ID: s.id}, nil
}

func (s *testService) Protocol() protocol.ID {
	return testProtocol
}

type testListener struct {
	mu        sync.Mutex
	successes int
	failures  int
	badPeers  int
}

func (l *testListener) RecordSuccess(peerID core.PeerID, latency time.Duration) {
	l.mu.Lock()
	l.successes++
	l.mu.Unlock()
}

func (l *testListener) RecordFailure(peerID core.PeerID, latency time.Duration) {
	l.mu.Lock()
	l.failures++
	l.mu.Unlock()
}

func (l *testListener) RecordBadPeer(peerID core.PeerID) {
	l.mu.Lock()
	l.badPeers++
	l.mu.Unlock()
}

type RPCTestSuite struct {
	suite.Suite

	servers     []Server
	serverHosts []host.Host

	client     Client
	clientHost host.Host

	listener *testListener
}

func TestRPCTestSuite(t *testing.T) {
	suite.Run(t, new(RPCTestSuite))
}

func (s *RPCTestSuite) SetupSuite() {
	require := require.New(s.T())

	newHost := func() host.Host {
		listenAddr, err := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/0")
		require.NoError(err, "NewMultiaddr failed")

		host, err := libp2p.New(
			libp2p.ListenAddrs(listenAddr),
		)
		require.NoError(err, "libp2p.New failed")

		return host
	}

	// Prepare N servers.
	n := 4

	s.servers = make([]Server, 0, n)
	for i := 0; i < n; i++ {
		server := NewServer(testProtocol, &testService{id: i})
		s.servers = append(s.servers, server)
	}

	s.serverHosts = make([]host.Host, 0, 5)
	for _, server := range s.servers {
		serverHost := newHost()
		serverHost.SetStreamHandler(server.Protocol(), server.HandleStream)

		s.serverHosts = append(s.serverHosts, serverHost)
	}

	// Prepare 1 client.
	s.clientHost = newHost()
	s.client = NewClient(s.clientHost, testProtocol)

	// Prepare listener.
	s.listener = &testListener{}
	s.client.RegisterListener(s.listener)

	// Connect client to all servers.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for _, serverHost := range s.serverHosts {
		err := s.clientHost.Connect(ctx, peer.AddrInfo{
			ID:    serverHost.ID(),
			Addrs: serverHost.Addrs(),
		})
		require.NoError(err)
	}
}

func (s *RPCTestSuite) TearDownSuite() {
	for _, h := range s.serverHosts {
		h.Close()
	}
	s.clientHost.Close()
}

func (s *RPCTestSuite) SetupTest() {
	s.listener.successes = 0
	s.listener.failures = 0
	s.listener.badPeers = 0
}

func (s *RPCTestSuite) TestCall() {
	require := require.New(s.T())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s.Run("Happy path", func() {
		peer := s.serverHosts[2].ID()
		var rsp testResponse
		pf, err := s.client.Call(ctx, peer, testMethod, &testRequest{}, &rsp)
		require.NoError(err, "Call failed")
		require.Equal(2, rsp.ID)
		require.Equal(peer, pf.PeerID())

		require.Equal(0, s.listener.successes)
		require.Equal(0, s.listener.failures)
		require.Equal(0, s.listener.badPeers)
	})

	s.Run("Peer returns an error", func() {
		peer := s.serverHosts[3].ID()
		var rsp testResponse
		_, err := s.client.Call(ctx, peer, "404", &testRequest{}, &rsp)
		require.Error(err, "Call did not fail")

		require.Equal(0, s.listener.successes)
		require.Equal(1, s.listener.failures)
		require.Equal(0, s.listener.badPeers)
	})
}

func (s *RPCTestSuite) TestCallOne() {
	require := require.New(s.T())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s.Run("Happy path", func() {
		peers := make([]peer.ID, 0, len(s.serverHosts))
		for _, h := range s.serverHosts {
			peers = append(peers, h.ID())
		}
		var rsp testResponse
		pf, err := s.client.CallOne(ctx, peers, testMethod, &testRequest{}, &rsp)
		require.NoError(err, "CallOne failed")
		require.Equal(2, rsp.ID)
		require.Equal(peers[2], pf.PeerID())

		require.Equal(0, s.listener.successes)
		require.Equal(2, s.listener.failures)
		require.Equal(0, s.listener.badPeers)
	})

	s.Run("All peers return an error", func() {
		peers := make([]peer.ID, 0, len(s.serverHosts))
		for i, h := range s.serverHosts {
			if i < 2 {
				peers = append(peers, h.ID())
			}
		}
		var rsp testResponse
		_, err := s.client.CallOne(ctx, peers, testMethod, &testRequest{}, &rsp)
		require.Error(err, "CallOne did not fail")

		require.Equal(0, s.listener.successes)
		require.Equal(4, s.listener.failures)
		require.Equal(0, s.listener.badPeers)
	})
}

func (s *RPCTestSuite) TestCallMulti() {
	require := require.New(s.T())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s.Run("Happy path", func() {
		peers := make([]peer.ID, 0, len(s.serverHosts))
		for _, h := range s.serverHosts {
			peers = append(peers, h.ID())
		}
		var rsp testResponse
		rsps, pfs, err := s.client.CallMulti(ctx, peers, testMethod, &testRequest{}, &rsp)
		require.NoError(err, "CallMulti failed")
		require.Equal(2, len(rsps))
		require.Equal(2, len(pfs))

		require.Equal(0, s.listener.successes)
		require.Equal(2, s.listener.failures)
		require.Equal(0, s.listener.badPeers)
	})

	s.Run("All peers return an error", func() {
		peers := make([]peer.ID, 0, len(s.serverHosts))
		for i, h := range s.serverHosts {
			if i < 2 {
				peers = append(peers, h.ID())
			}
		}
		var rsp testResponse
		rsps, pfs, err := s.client.CallMulti(ctx, peers, testMethod, &testRequest{}, &rsp)
		require.NoError(err, "CallMulti failed")
		require.Equal(0, len(rsps))
		require.Equal(0, len(pfs))

		require.Equal(0, s.listener.successes)
		require.Equal(4, s.listener.failures)
		require.Equal(0, s.listener.badPeers)
	})
}

func (s *RPCTestSuite) TestListener() {
	require := require.New(s.T())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	peer := s.serverHosts[2].ID()
	var rsp testResponse
	pf, err := s.client.Call(ctx, peer, testMethod, &testRequest{}, &rsp)
	require.NoError(err, "Call failed")

	test := func(l *testListener, s, f, b int) {
		require.Equal(s, l.successes)
		require.Equal(f, l.failures)
		require.Equal(b, l.badPeers)
	}

	s.Run("Happy path", func() {
		firstListener := testListener{}
		test(&firstListener, 0, 0, 0)

		secondListener := testListener{}
		test(&secondListener, 0, 0, 0)

		s.client.RegisterListener(&firstListener)
		pf.RecordSuccess()
		test(&firstListener, 1, 0, 0)
		pf.RecordFailure()
		test(&firstListener, 1, 1, 0)
		pf.RecordBadPeer()
		test(&firstListener, 1, 1, 1)
		test(&secondListener, 0, 0, 0)

		s.client.RegisterListener(&secondListener)
		pf.RecordSuccess()
		pf.RecordFailure()
		pf.RecordBadPeer()
		test(&firstListener, 2, 2, 2)
		test(&secondListener, 1, 1, 1)

		s.client.UnregisterListener(&firstListener)
		pf.RecordSuccess()
		pf.RecordFailure()
		pf.RecordBadPeer()
		test(&secondListener, 2, 2, 2)
		test(&firstListener, 2, 2, 2)

		s.client.UnregisterListener(&secondListener)
		pf.RecordSuccess()
		pf.RecordFailure()
		pf.RecordBadPeer()
		test(&secondListener, 2, 2, 2)
		test(&firstListener, 2, 2, 2)
	})

	s.Run("Register/unregister multiple times", func() {
		listener := testListener{}

		for i := 0; i < 5; i++ {
			s.client.RegisterListener(&listener)
		}
		pf.RecordSuccess()
		test(&listener, 1, 0, 0)

		for i := 0; i < 10; i++ {
			s.client.UnregisterListener(&listener)
		}
		pf.RecordSuccess()
		test(&listener, 1, 0, 0)

		s.client.RegisterListener(&listener)
		pf.RecordSuccess()
		test(&listener, 2, 0, 0)
	})
}
