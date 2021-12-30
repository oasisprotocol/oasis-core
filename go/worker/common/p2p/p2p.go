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
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tuplehash"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

// messageIdContext is the domain separation context for computing message identifier hashes.
var messageIdContext = []byte("oasis-core/p2p: message id")

// TopicKind is the gossipsub topic kind.
type TopicKind string

const (
	// TopicKindCommittee is the topic kind for the topic that is used to gossip batch proposals
	// and other committee messages.
	TopicKindCommittee TopicKind = "committee"
	// TopicKindTx is the topic kind for the topic that is used to gossip transactions.
	TopicKindTx TopicKind = "tx"
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
	topics            map[common.Namespace]map[TopicKind]*topicHandler

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
	allPeers := p.pubsub.ListPeers(p.topicIDForRuntime(runtimeID, TopicKindCommittee))
	allPeers = append(allPeers, p.pubsub.ListPeers(p.topicIDForRuntime(runtimeID, TopicKindTx))...)

	var peers []string
	for _, peerID := range allPeers {
		addrs := p.host.Peerstore().Addrs(peerID)
		if len(addrs) == 0 {
			continue
		}
		if reachableAddrs := filterGloballyReachableAddresses(addrs); len(reachableAddrs) > 0 {
			addrs = reachableAddrs
		}

		peers = append(peers, fmt.Sprintf("%s/p2p/%s", addrs[0].String(), peerID.Pretty()))
	}
	return peers
}

func filterGloballyReachableAddresses(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	ret := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, addr := range addrs {
		// Ugh, this multiaddr stuff is extremely obnoxious to work with.
		addrStr, err := addr.ValueForProtocol(multiaddr.P_IP4)
		if err != nil {
			addrStr, err = addr.ValueForProtocol(multiaddr.P_IP6)
			if err != nil {
				continue
			}
		}

		ip := net.ParseIP(addrStr)
		if ip == nil {
			continue
		}
		if !common.IsProbablyGloballyReachable(ip) {
			continue
		}

		// I have no idea if multiaddr.Multiaddr copies correctly.
		addrCopy, err := multiaddr.NewMultiaddr(addr.String())
		if err != nil {
			continue
		}
		ret = append(ret, addrCopy)
	}
	return ret
}

func (p *P2P) publish(ctx context.Context, runtimeID common.Namespace, kind TopicKind, msg interface{}) {
	rawMsg := cbor.Marshal(msg)

	p.RLock()
	defer p.RUnlock()

	topics := p.topics[runtimeID]
	if topics == nil {
		p.logger.Error("attempted to publish message for unknown runtime ID",
			"runtime_id", runtimeID,
			"kind", kind,
		)
		return
	}

	h := topics[kind]
	if h == nil {
		p.logger.Error("attempted to publish message for unsupported topic kind",
			"runtime_id", runtimeID,
			"kind", kind,
		)
		return
	}

	if err := h.tryPublishing(rawMsg); err != nil {
		h.logger.Error("failed to publish message to the network",
			"err", err,
		)
	}

	p.logger.Debug("published message",
		"runtime_id", runtimeID,
		"kind", kind,
	)
}

// PublishCommittee publishes a committee message.
func (p *P2P) PublishCommittee(ctx context.Context, runtimeID common.Namespace, msg *CommitteeMessage) {
	p.publish(ctx, runtimeID, TopicKindCommittee, msg)
}

// PublishCommittee publishes a transaction message.
func (p *P2P) PublishTx(ctx context.Context, runtimeID common.Namespace, msg TxMessage) {
	p.publish(ctx, runtimeID, TopicKindTx, msg)
}

// RegisterHandler registers a message handler for the specified runtime and topic kind.
func (p *P2P) RegisterHandler(runtimeID common.Namespace, kind TopicKind, handler Handler) {
	p.Lock()
	defer p.Unlock()

	topics := p.topics[runtimeID]
	if topics == nil {
		topics = make(map[TopicKind]*topicHandler)
		p.topics[runtimeID] = topics
	}

	if topics[kind] != nil {
		panic(fmt.Sprintf("worker/common/p2p: handler for topic kind '%s' already registered", kind))
	}

	topicID, h, err := newTopicHandler(p, runtimeID, kind, handler)
	if err != nil {
		panic(fmt.Sprintf("worker/common/p2p: failed to initialize topic handler: %s", err))
	}
	topics[kind] = h
	_ = p.pubsub.RegisterTopicValidator(
		topicID,
		h.topicMessageValidator,
		pubsub.WithValidatorConcurrency(viper.GetInt(CfgP2PValidateConcurrency)),
	)

	p.logger.Debug("registered new topic handler",
		"runtime_id", runtimeID,
		"kind", kind,
	)
}

func (p *P2P) handleConnection(conn core.Conn) {
	if conn.Stat().Direction != network.DirInbound {
		return
	}

	p.logger.Debug("new connection from peer",
		"peer_id", conn.RemotePeer(),
	)
}

func (p *P2P) topicIDForRuntime(runtimeID common.Namespace, kind TopicKind) string {
	return fmt.Sprintf("%s/%d/%s/%s",
		p.chainContext,
		version.RuntimeCommitteeProtocol.Major,
		runtimeID.String(),
		kind,
	)
}

// GetMinRepublishInterval returns the minimum republish interval that needs to be respected by
// the caller when publishing the same message. If Publish is called for the same message more
// quickly, the message may be dropped and not published.
func (p *P2P) GetMinRepublishInterval() time.Duration {
	return pubsub.TimeCacheDuration + 5*time.Second
}

func messageIdFn(pmsg *pb.Message) string {
	// id := TupleHash[messageIdContext](topic, data)
	h := tuplehash.New256(32, messageIdContext)
	_, _ = h.Write([]byte(pmsg.GetTopic()))
	_, _ = h.Write(pmsg.Data)
	return string(h.Sum(nil))
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
		pubsub.WithMessageIdFn(messageIdFn),
	)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to initialize libp2p gossipsub: %w", err)
	}

	chainContext, err := consensus.GetChainContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to get consensus chain context: %w", err)
	}

	p := &P2P{
		PeerManager:       newPeerManager(ctx, host, consensus),
		ctx:               ctx,
		chainContext:      chainContext,
		host:              host,
		pubsub:            pubsub,
		registerAddresses: registerAddresses,
		topics:            make(map[common.Namespace]map[TopicKind]*topicHandler),
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
