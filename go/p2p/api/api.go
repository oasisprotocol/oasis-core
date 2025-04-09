// Package api implements the P2P API.
package api

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

// TopicKind is the gossipsub topic kind.
type TopicKind string

const (
	// TopicKindCommittee is the topic kind for the topic that is used to gossip batch proposals
	// and other committee messages.
	TopicKindCommittee TopicKind = "committee"
	// TopicKindTx is the topic kind for the topic that is used to gossip transactions.
	TopicKindTx TopicKind = "tx"
)

// Status is the P2P status of a node.
type Status struct {
	// PubKey is the public key used for P2P communication.
	PubKey signature.PublicKey `json:"pub_key"`

	// PeerID is the peer ID derived by hashing peer's public key.
	PeerID peer.ID `json:"peer_id"`

	// Addresses is a list of configured P2P addresses used when registering the node.
	Addresses []node.Address `json:"addresses"`

	// NumPeers is the number of connected peers.
	NumPeers int `json:"num_peers"`

	// NumConnections is the number of peer connections.
	NumConnections int `json:"num_connections"`

	// Protocols is a set of registered protocols together with the number of connected peers.
	Protocols map[core.ProtocolID]int `json:"protocols"`

	// Topics is a set of registered topics together with the number of connected peers.
	Topics map[string]int `json:"topics"`
}

// Service is a P2P node service interface.
type Service interface {
	service.BackgroundService

	// GetStatus returns the P2P status of the node.
	GetStatus() *Status

	// Addresses returns the P2P addresses of the node.
	Addresses() []node.Address

	// Peers returns a list of connected P2P peers for the given runtime.
	Peers(runtimeID common.Namespace) []string

	// Publish publishes the given message to the given topic.
	Publish(ctx context.Context, topic string, msg any)

	// RegisterHandler registers a message handler for the specified runtime and topic kind.
	RegisterHandler(topic string, handler Handler)

	// BlockPeer blocks a specific peer from being used by the local node.
	BlockPeer(peerID core.PeerID)

	// Host returns the P2P host.
	Host() core.Host

	// PeerManager returns the P2P peer manager.
	PeerManager() PeerManager

	// RegisterProtocol starts tracking and managing peers that support the given protocol.
	RegisterProtocol(p core.ProtocolID, minPeers int, totalPeers int)

	// RegisterProtocolServer registers a protocol server for the given protocol.
	RegisterProtocolServer(srv rpc.Server)

	// GetMinRepublishInterval returns the minimum republish interval that needs to be respected by
	// the caller when publishing the same message. If Publish is called for the same message more
	// quickly, the message may be dropped and not published.
	GetMinRepublishInterval() time.Duration
}

// Handler is a handler for P2P messages.
type Handler interface {
	// DecodeMessage decodes the given incoming message.
	DecodeMessage(msg []byte) (any, error)

	// AuthorizeMessage handles authorizing an incoming message.
	//
	// The message handler will be re-invoked on error with a periodic backoff unless errors are
	// wrapped via `p2pError.Permanent`.
	AuthorizeMessage(ctx context.Context, peerID signature.PublicKey, msg any) error

	// HandleMessage handles an incoming message from a peer.
	//
	// The message handler will be re-invoked on error with a periodic backoff unless errors are
	// wrapped via `p2pError.Permanent`.
	HandleMessage(ctx context.Context, peerID signature.PublicKey, msg any, isOwn bool) error
}

// PeerManager is an interface for managing peers in the P2P network.
type PeerManager interface {
	// PeerRegistry returns the peer registry.
	PeerRegistry() PeerRegistry

	// PeerTagger returns the peer tagger.
	PeerTagger() PeerTagger
}

// PeerRegistry is an interface for accessing peer information from the registry.
type PeerRegistry interface {
	// Initialized returns a channel that will be closed once the first node refresh event from
	// the registry is received.
	Initialized() <-chan struct{}

	// NumPeers returns the number of registered peers.
	NumPeers() int
}

// PeerTagger is an interface for tagging important peers.
type PeerTagger interface {
	// SetPeerImportance configures peer importance for the given list of peers.
	//
	// This makes it less likely for those peers to be pruned.
	SetPeerImportance(kind ImportanceKind, runtimeID common.Namespace, pids []peer.ID)
}

// SeedService is a P2P node service interface.
type SeedService interface {
	service.BackgroundService

	// Addresses returns the listen addresses of the host.
	Addresses() []string

	// Peers returns a list of peers located in the peer store.
	Peers() []string
}
