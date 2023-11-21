package rpc

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

var errUnsupported = fmt.Errorf("unsupported: p2p is disabled")

type nopPeerManager struct{}

// Implements PeerManager.
func (*nopPeerManager) AddPeer(peer.ID) {
}

// Implements PeerManager.
func (*nopPeerManager) GetBestPeers(...BestPeersOption) []peer.ID {
	return nil
}

// Implements PeerManager.
func (*nopPeerManager) RecordBadPeer(peer.ID) {
}

// Implements PeerManager.
func (*nopPeerManager) RecordFailure(peer.ID, time.Duration) {
}

// Implements PeerManager.
func (*nopPeerManager) RecordSuccess(peer.ID, time.Duration) {
}

// Implements PeerManager.
func (*nopPeerManager) RemovePeer(peer.ID) {
}

// Implements PeersUpdates.
func (*nopPeerManager) WatchUpdates() (<-chan *PeerUpdate, pubsub.ClosableSubscription, error) {
	return nil, nil, errUnsupported
}

type nopClient struct{}

// Implements Client.
func (c *nopClient) Call(
	context.Context,
	peer.ID,
	string,
	interface{},
	interface{},
	...CallOption,
) (PeerFeedback, error) {
	return nil, errUnsupported
}

// Implements Client.
func (c *nopClient) CallOne(
	context.Context,
	[]peer.ID,
	string,
	interface{},
	interface{},
	...CallOption,
) (PeerFeedback, error) {
	return nil, errUnsupported
}

// Implements Client.
func (c *nopClient) CallMulti(
	context.Context,
	[]peer.ID,
	string,
	interface{},
	interface{},
	...CallMultiOption,
) ([]interface{}, []PeerFeedback, error) {
	return nil, nil, errUnsupported
}

// Implements Client.
func (c *nopClient) Close(
	peer.ID,
) error {
	return nil
}

// Implements Client.
func (c *nopClient) RegisterListener(ClientListener) {}

// Implements Client.
func (c *nopClient) UnregisterListener(ClientListener) {}
