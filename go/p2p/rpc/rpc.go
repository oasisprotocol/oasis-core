// Package rpc provides tools for building simple RPC protocols via libp2p.
package rpc

import (
	"context"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"
)

const codecModuleName = "p2p/rpc"

// P2P is a P2P interface that the RPC protocols need.
type P2P interface {
	// BlockPeer blocks a specific peer from being used by the local node.
	BlockPeer(peerID core.PeerID)

	// RegisterProtocol starts tracking and managing peers that support given protocol.
	RegisterProtocol(p core.ProtocolID, minPeers int, totalPeers int)

	// Host returns the P2P host.
	Host() core.Host
}

// contextKeyPeerAddrInfo is the context key used for storing the peer addr info.
type contextKeyPeerAddrInfo struct{}

// WithPeerAddrInfo creates a new context with the peer addr info value set.
func WithPeerAddrInfo(parent context.Context, peerAddrInfo peer.AddrInfo) context.Context {
	return context.WithValue(parent, contextKeyPeerAddrInfo{}, peerAddrInfo)
}

// PeerIDFromContext looks up the peer ID value in the given context.
func PeerIDFromContext(ctx context.Context) (core.PeerID, bool) {
	peerAddrInfo, ok := ctx.Value(contextKeyPeerAddrInfo{}).(peer.AddrInfo)
	if !ok {
		return "", false
	}
	return peerAddrInfo.ID, true
}

// PeerAddrInfoFromContext looks up the peer addr info value in the given context.
func PeerAddrInfoFromContext(ctx context.Context) (peer.AddrInfo, bool) {
	peerAddrInfo, ok := ctx.Value(contextKeyPeerAddrInfo{}).(peer.AddrInfo)
	return peerAddrInfo, ok
}
