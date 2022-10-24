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
func (*nopPeerManager) GetBestPeers() []peer.ID {
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

type nopClient struct {
	*nopPeerManager
}

// Implements Client.
func (c *nopClient) Call(
	ctx context.Context,
	method string,
	body, rsp interface{},
	maxPeerResponseTime time.Duration,
	opts ...CallOption,
) (PeerFeedback, error) {
	return nil, fmt.Errorf("unsupported: p2p is disabled")
}

// Implements Client.
func (c *nopClient) CallMulti(
	ctx context.Context,
	method string,
	body, rspTyp interface{},
	maxPeerResponseTime time.Duration,
	maxParallelRequests uint,
	opts ...CallMultiOption,
) ([]interface{}, []PeerFeedback, error) {
	return nil, nil, fmt.Errorf("unsupported: p2p is disabled")
}
