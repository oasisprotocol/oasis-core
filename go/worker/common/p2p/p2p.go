// Package p2p implements the worker committee gossip network.
package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	core "github.com/libp2p/go-libp2p-core"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/transport"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

var allowUnroutableAddresses bool

// DebugForceAllowUnroutableAddresses allows unroutable addresses.
func DebugForceAllowUnroutableAddresses() {
	allowUnroutableAddresses = true
}

// P2P is a peer-to-peer node using libp2p.
type P2P struct {
	sync.RWMutex
	*PeerManager

	ctx context.Context

	chainContext string

	host   core.Host
	pubsub *pubsub.PubSub

	registerAddresses []multiaddr.Multiaddr
	topics            map[common.Namespace]*topicHandler

	logger *logging.Logger
}

// Addresses returns the P2P addresses of the node.
func (p *P2P) Addresses() []node.Address {
	if p == nil {
		return nil
	}

	var addrs []multiaddr.Multiaddr
	if len(p.registerAddresses) == 0 {
		addrs = p.host.Addrs()
	} else {
		addrs = p.registerAddresses
	}

	allowUnroutable := allowUnroutableAddresses

	var addresses []node.Address
	for _, v := range addrs {
		netAddr, err := manet.ToNetAddr(v)
		if err != nil {
			panic(err)
		}
		tcpAddr := (netAddr).(*net.TCPAddr)
		nodeAddr := node.Address{TCPAddr: *tcpAddr}
		if err := registryAPI.VerifyAddress(nodeAddr, allowUnroutable); err != nil {
			continue
		}

		addresses = append(addresses, nodeAddr)
	}

	return addresses
}

// Peers returns a list of connected P2P peers for the given runtime.
func (p *P2P) Peers(runtimeID common.Namespace) []string {
	var peers []string
	for _, peerID := range p.pubsub.ListPeers(p.topicIDForRuntime(runtimeID)) {
		addrs := p.host.Peerstore().Addrs(peerID)
		if len(addrs) == 0 {
			continue
		}

		peers = append(peers, fmt.Sprintf("%s/p2p/%s", addrs[0].String(), peerID.Pretty()))
	}
	return peers
}

// Publish publishes a message to the gossip network.
func (p *P2P) Publish(ctx context.Context, runtimeID common.Namespace, msg *Message) {
	rawMsg := cbor.Marshal(msg)

	p.RLock()
	defer p.RUnlock()

	h := p.topics[runtimeID]
	if h == nil {
		p.logger.Error("attempted to publish message for unknown runtime ID",
			"runtime_id", runtimeID,
		)
		return
	}

	if err := h.tryPublishing(rawMsg); err != nil {
		h.logger.Error("failed to publish message to the network",
			"err", err,
		)
	}
}

// RegisterHandler registers a message handler for the specified runtime.
// If multiple handlers are registered for the same runtime, each of the
// handlers will get invoked.
func (p *P2P) RegisterHandler(runtimeID common.Namespace, handler Handler) {
	p.Lock()
	defer p.Unlock()

	topic := p.topics[runtimeID]

	switch topic {
	case nil:
		// New topic.
		topicID, h, err := newTopicHandler(p, runtimeID, []Handler{handler})
		if err != nil {
			panic(fmt.Sprintf("worker/common/p2p: failed to initialize topic handler: %s", err))
		}
		p.topics[runtimeID] = h
		_ = p.pubsub.RegisterTopicValidator(
			topicID,
			h.topicMessageValidator,
			pubsub.WithValidatorConcurrency(viper.GetInt(CfgP2PValidateConcurrency)),
		)
	default:
		topic.handlersLock.Lock()
		defer topic.handlersLock.Unlock()
		// Existing topic, add handler.
		topic.handlers = append(topic.handlers, handler)
	}
}

func (p *P2P) handleConnection(conn core.Conn) {
	if conn.Stat().Direction != network.DirInbound {
		return
	}

	p.logger.Debug("new connection from peer",
		"peer_id", conn.RemotePeer(),
	)
}

func (p *P2P) topicIDForRuntime(runtimeID common.Namespace) string {
	return fmt.Sprintf("%s/%d/%s",
		p.chainContext,
		version.RuntimeCommitteeProtocol.Major,
		runtimeID.String(),
	)
}

// New creates a new P2P node.
func New(ctx context.Context, identity *identity.Identity, consensus consensus.Backend) (*P2P, error) {
	// Instantiate the libp2p host.
	addresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgP2pAddresses))
	if err != nil {
		return nil, err
	}
	port := uint16(viper.GetInt(CfgP2pPort))

	var registerAddresses []multiaddr.Multiaddr
	for _, addr := range addresses {
		var mAddr multiaddr.Multiaddr
		mAddr, err = manet.FromNetAddr(&addr.TCPAddr)
		if err != nil {
			return nil, err
		}
		registerAddresses = append(registerAddresses, mAddr)
	}

	sourceMultiAddr, _ := multiaddr.NewMultiaddr(
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
	)

	// Oh hey, they finally got around to fixing the NAT traversal code,
	// so if people feel brave enough to want to interact with the
	// mountain of terrible uPNP/NAT-PMP implementations out there,
	// they can.
	host, err := libp2p.New(
		ctx,
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(signerToPrivKey(identity.P2PSigner)),
	)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to initialize libp2p host: %w", err)
	}

	// Initialize the gossipsub router.
	pubsub, err := pubsub.NewGossipSub(
		ctx,
		host,
		pubsub.WithMessageSigning(true),
		pubsub.WithStrictSignatureVerification(true),
		pubsub.WithFloodPublish(true),
		pubsub.WithPeerOutboundQueueSize(viper.GetInt(CfgP2PPeerOutboundQueueSize)),
		pubsub.WithValidateQueueSize(viper.GetInt(CfgP2PValidateQueueSize)),
		pubsub.WithValidateThrottle(viper.GetInt(CfgP2PValidateThrottle)),
		pubsub.WithMessageIdFn(func(pmsg *pb.Message) string {
			h := hash.NewFromBytes(pmsg.Data)
			return string(h[:])
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to initialize libp2p gossipsub: %w", err)
	}

	doc, err := consensus.GetGenesisDocument(ctx)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to get consensus genesis document: %w", err)
	}

	p := &P2P{
		PeerManager:       newPeerManager(ctx, host, consensus),
		ctx:               ctx,
		chainContext:      doc.ChainContext(),
		host:              host,
		pubsub:            pubsub,
		registerAddresses: registerAddresses,
		topics:            make(map[common.Namespace]*topicHandler),
		logger:            logging.GetLogger("worker/common/p2p"),
	}
	p.host.Network().SetConnHandler(p.handleConnection)

	p.logger.Info("p2p host initialized",
		"address", fmt.Sprintf("%+v", host.Addrs()),
	)

	return p, nil
}

func init() {
	// Make sure to decrease (global!) transport timeouts.
	transport.AcceptTimeout = 5 * time.Second
}
