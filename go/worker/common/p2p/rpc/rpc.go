// Package rpc provides tools for building simple RPC protocols via libp2p.
package rpc

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

const codecModuleName = "p2p/rpc"

// P2P is a P2P interface that the RPC protocols need.
type P2P interface {
	// BlockPeer blocks a specific peer from being used by the local node.
	BlockPeer(peerID core.PeerID)

	// GetHost returns the P2P host.
	GetHost() core.Host
}

// NewRuntimeProtocolID generates a protocol identifier for a protocol supported for a specific
// runtime. This makes it so that one doesn't need additional checks to ensure that a peer supports
// the given protocol for the given runtime.
func NewRuntimeProtocolID(runtimeID common.Namespace, protocolID string, version version.Version) protocol.ID {
	return protocol.ID(fmt.Sprintf("/oasis/%s/%s/%s", protocolID, runtimeID.Hex(), version.MaskNonMajor()))
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
