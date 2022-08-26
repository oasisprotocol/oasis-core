// Package api implements the P2P API.
package api

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
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

// Service is a P2P node service interface.
type Service interface {
	service.BackgroundService

	// Addresses returns the P2P addresses of the node.
	Addresses() []node.Address

	// Peers returns a list of connected P2P peers for the given runtime.
	Peers(runtimeID common.Namespace) []string

	// PublishCommittee publishes a committee message.
	PublishCommittee(ctx context.Context, runtimeID common.Namespace, msg *CommitteeMessage)

	// PublishTx publishes a transaction message.
	PublishTx(ctx context.Context, runtimeID common.Namespace, msg TxMessage)

	// RegisterHandler registers a message handler for the specified runtime and topic kind.
	RegisterHandler(runtimeID common.Namespace, kind TopicKind, handler Handler)

	// BlockPeer blocks a specific peer from being used by the local node.
	BlockPeer(peerID core.PeerID)

	// GetHost returns the P2P host.
	GetHost() core.Host

	// RegisterProtocolServer registers a protocol server for the given protocol.
	RegisterProtocolServer(srv rpc.Server)

	// GetMinRepublishInterval returns the minimum republish interval that needs to be respected by
	// the caller when publishing the same message. If Publish is called for the same message more
	// quickly, the message may be dropped and not published.
	GetMinRepublishInterval() time.Duration

	// SetNodeImportance configures node importance for the given set of nodes.
	//
	// This makes it less likely for those nodes to be pruned.
	SetNodeImportance(kind ImportanceKind, runtimeID common.Namespace, p2pIDs map[signature.PublicKey]bool)
}

// Handler is a handler for P2P messages.
type Handler interface {
	// DecodeMessage decodes the given incoming message.
	DecodeMessage(msg []byte) (interface{}, error)

	// AuthorizeMessage handles authorizing an incoming message.
	//
	// The message handler will be re-invoked on error with a periodic backoff unless errors are
	// wrapped via `p2pError.Permanent`.
	AuthorizeMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}) error

	// HandleMessage handles an incoming message from a peer.
	//
	// The message handler will be re-invoked on error with a periodic backoff unless errors are
	// wrapped via `p2pError.Permanent`.
	HandleMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}, isOwn bool) error
}

// PublicKeyToPeerID converts a public key to a peer identifier.
func PublicKeyToPeerID(pk signature.PublicKey) (core.PeerID, error) {
	pubKey, err := publicKeyToPubKey(pk)
	if err != nil {
		return "", err
	}

	id, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	return id, nil
}

const peerTagImportancePrefix = "oasis-core/importance"

// ImportanceKind is the node importance kind.
type ImportanceKind uint8

const (
	ImportantNodeCompute    = 1
	ImportantNodeKeyManager = 2
)

// Tag returns the connection manager tag associated with the given importance kind.
func (ik ImportanceKind) Tag(runtimeID common.Namespace) string {
	switch ik {
	case ImportantNodeCompute:
		return peerTagImportancePrefix + "/compute/" + runtimeID.String()
	case ImportantNodeKeyManager:
		return peerTagImportancePrefix + "/keymanager/" + runtimeID.String()
	default:
		panic(fmt.Errorf("unsupported tag: %d", ik))
	}
}

// TagValue returns the connection manager tag value associated with the given importance kind.
func (ik ImportanceKind) TagValue() int {
	switch ik {
	case ImportantNodeCompute, ImportantNodeKeyManager:
		return 1000
	default:
		panic(fmt.Errorf("unsupported tag: %d", ik))
	}
}
