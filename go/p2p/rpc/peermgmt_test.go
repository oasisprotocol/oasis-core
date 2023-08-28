package rpc

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

type testP2P struct {
	host host.Host
}

// BlockPeer implements P2P.
func (*testP2P) BlockPeer(peer.ID) {
}

// Host implements P2P.
func (t *testP2P) Host() host.Host {
	return t.host
}

// RegisterProtocol implements P2P.
func (*testP2P) RegisterProtocol(protocol.ID, int, int) {
}

func TestWatchUpdates(t *testing.T) {
	require := require.New(t)

	// Prepare a p2p host.
	listenAddr, err := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/0")
	require.NoError(err, "NewMultiaddr failed")
	host, err := libp2p.New(
		libp2p.ListenAddrs(listenAddr),
	)
	require.NoError(err, "libp2p.New failed")
	defer host.Close()

	peerMgr := NewPeerManager(&testP2P{host}, testProtocol)

	ch, sub, err := peerMgr.WatchUpdates()
	require.NoError(err, "WatchUpdates")
	defer sub.Close()

	// No events expected.
	select {
	case ev := <-ch:
		t.Fatalf("received unexpected event: %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}

	peer1, peer2, peer3 := core.PeerID("peer-1"), core.PeerID("peer-2"), core.PeerID("peer-3")

	// Add/remove peers.
	peerMgr.AddPeer(peer1)
	peerMgr.AddPeer(peer2)
	peerMgr.RecordBadPeer(peer1)
	peerMgr.RecordBadPeer(peer1)
	peerMgr.AddPeer(peer3)
	peerMgr.AddPeer(peer3)
	peerMgr.RemovePeer(peer2)
	peerMgr.RemovePeer(peer2)

	// Ensure expected events are received.
	expectedEvents := []*PeerUpdate{
		{ID: peer1, PeerAdded: &PeerAdded{}},
		{ID: peer2, PeerAdded: &PeerAdded{}},
		{ID: peer1, PeerRemoved: &PeerRemoved{BadPeer: true}},
		{ID: peer3, PeerAdded: &PeerAdded{}},
		{ID: peer2, PeerRemoved: &PeerRemoved{}},
	}
	for _, next := range expectedEvents {
		select {
		case ev := <-ch:
			require.Equal(next, ev, "should receive expected event")
		case <-time.After(2 * time.Second):
			t.Fatalf("failed to receive expected event: %+v", next)
		}
	}

	// No more events expected.
	select {
	case ev := <-ch:
		t.Fatalf("received unexpected event: %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}
