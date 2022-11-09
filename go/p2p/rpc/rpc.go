// Package rpc provides tools for building simple RPC protocols via libp2p.
package rpc

import (
	"context"

	"github.com/libp2p/go-libp2p/core"
)

const codecModuleName = "p2p/rpc"

// P2P is a P2P interface that the RPC protocols need.
type P2P interface {
	// BlockPeer blocks a specific peer from being used by the local node.
	BlockPeer(peerID core.PeerID)

	// RegisterProtocol starts tracking and managing peers that support given protocol.
	RegisterProtocol(p core.ProtocolID, min int, total int)

	// Host returns the P2P host.
	Host() core.Host
}

// contextKeyPeerID is the context key used for storing the peer ID.
type contextKeyPeerID struct{}

// WithPeerID creates a new context with the peer ID value set.
func WithPeerID(parent context.Context, peerID core.PeerID) context.Context {
	return context.WithValue(parent, contextKeyPeerID{}, peerID)
}

// PeerIDFromContext looks up the peer ID value in the given context.
func PeerIDFromContext(ctx context.Context) (core.PeerID, bool) {
	peerID, ok := ctx.Value(contextKeyPeerID{}).(core.PeerID)
	return peerID, ok
}
