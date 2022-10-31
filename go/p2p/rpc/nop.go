package rpc

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

type nopPeerManager struct{}

// Implements PeerManager.
func (*nopPeerManager) AddPeer(peerID peer.ID) {
}

// Implements PeerManager.
func (*nopPeerManager) GetBestPeers(opts ...BestPeersOption) []peer.ID {
	return nil
}

// Implements PeerManager.
func (*nopPeerManager) RecordBadPeer(peerID peer.ID) {
}

// Implements PeerManager.
func (*nopPeerManager) RecordFailure(peerID peer.ID, latency time.Duration) {
}

// Implements PeerManager.
func (*nopPeerManager) RecordSuccess(peerID peer.ID, latency time.Duration) {
}

// Implements PeerManager.
func (*nopPeerManager) RemovePeer(peerID peer.ID) {
}

type nopClient struct{}

// Implements Client.
func (c *nopClient) Call(
	ctx context.Context,
	peer peer.ID,
	method string,
	body, rsp interface{},
	opts ...CallOption,
) (PeerFeedback, error) {
	return nil, fmt.Errorf("unsupported: p2p is disabled")
}

// Implements Client.
func (c *nopClient) CallOne(
	ctx context.Context,
	peers []peer.ID,
	method string,
	body, rsp interface{},
	opts ...CallOption,
) (PeerFeedback, error) {
	return nil, fmt.Errorf("unsupported: p2p is disabled")
}

// Implements Client.
func (c *nopClient) CallMulti(
	ctx context.Context,
	peers []peer.ID,
	method string,
	body, rspTyp interface{},
	opts ...CallMultiOption,
) ([]interface{}, []PeerFeedback, error) {
	return nil, nil, fmt.Errorf("unsupported: p2p is disabled")
}

// Implements Client.
func (c *nopClient) RegisterListener(l ClientListener) {}

// Implements Client.
func (c *nopClient) UnregisterListener(l ClientListener) {}
