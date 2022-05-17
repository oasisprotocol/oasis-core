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
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/p2p/net/conngater"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
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
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

// peersHighWatermarkDelta specifies how many peers after the maximum peer count is reached we ask
// the connection manager to start pruning peers.
const peersHighWatermarkDelta = 30

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

	ctxCancel context.CancelFunc
	quitCh    chan struct{}

	chainContext string

	host   core.Host
	pubsub *pubsub.PubSub

	registerAddresses []multiaddr.Multiaddr
	topics            map[common.Namespace]map[TopicKind]*topicHandler

	logger *logging.Logger
}

// Cleanup performs the service specific post-termination cleanup.
func (p *P2P) Cleanup() {
}

// Name returns the service name.
func (p *P2P) Name() string {
	return "worker p2p"
}

// Start starts the service.
func (p *P2P) Start() error {
	// Unfortunately libp2p starts everything on construction.
	return nil
}

// Stop halts the service.
func (p *P2P) Stop() {
	p.ctxCancel()
	_ = p.host.Close() // This blocks until the host stops.
	close(p.quitCh)
}

// Quit returns a channel that will be closed when the service terminates.
func (p *P2P) Quit() <-chan struct{} {
	return p.quitCh
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
		nodeAddr := node.Address{
			IP:   tcpAddr.IP,
			Port: int64(tcpAddr.Port),
			Zone: tcpAddr.Zone,
		}

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
	peerMap := make(map[core.PeerID]bool)
	for _, peerID := range allPeers {
		if peerMap[peerID] {
			continue
		}
		peerMap[peerID] = true

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

func (p *P2P) topicIDForRuntime(runtimeID common.Namespace, kind TopicKind) string {
	return fmt.Sprintf("%s/%d/%s/%s",
		p.chainContext,
		version.RuntimeCommitteeProtocol.Major,
		runtimeID.String(),
		kind,
	)
}

// BlockPeer blocks a specific peer from being used by the local node.
func (p *P2P) BlockPeer(peerID core.PeerID) {
	p.logger.Warn("blocking peer",
		"peer_id", peerID,
	)

	p.pubsub.BlacklistPeer(peerID)
	p.PeerManager.blockPeer(peerID)
}

// GetHost returns the P2P host.
func (p *P2P) GetHost() core.Host {
	return p.host
}

// RegisterProtocolServer registers a protocol server for the given protocol.
func (p *P2P) RegisterProtocolServer(srv rpc.Server) {
	p.host.SetStreamHandler(srv.Protocol(), srv.HandleStream)

	p.logger.Info("registered protocol server",
		"protocol_id", srv.Protocol(),
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
func New(identity *identity.Identity, consensus consensus.Backend) (*P2P, error) {
	// Instantiate the libp2p host.
	addresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgP2pAddresses))
	if err != nil {
		return nil, err
	}
	port := uint16(viper.GetInt(CfgP2pPort))

	var registerAddresses []multiaddr.Multiaddr
	for _, addr := range addresses {
		var mAddr multiaddr.Multiaddr
		mAddr, err = manet.FromNetAddr(addr.ToTCPAddr())
		if err != nil {
			return nil, err
		}
		registerAddresses = append(registerAddresses, mAddr)
	}

	sourceMultiAddr, _ := multiaddr.NewMultiaddr(
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
	)

	// Set up a connection manager so we can limit the number of connections.
	low := int(viper.GetUint32(CfgP2PMaxNumPeers))
	cm, err := connmgr.NewConnManager(
		low,
		low+peersHighWatermarkDelta,
		connmgr.WithGracePeriod(viper.GetDuration(CfgP2PPeerGracePeriod)),
	)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to create connection manager: %w", err)
	}

	// Set up a connection gater.
	cg, err := conngater.NewBasicConnectionGater(nil)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to create connection gater: %w", err)
	}

	// Create the P2P host.
	host, err := libp2p.New(
		libp2p.UserAgent(fmt.Sprintf("oasis-core/%s", version.SoftwareVersion)),
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(signerToPrivKey(identity.P2PSigner)),
		libp2p.ConnectionManager(cm),
		libp2p.ConnectionGater(cg),
	)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to initialize libp2p host: %w", err)
	}

	// Initialize the gossipsub router.
	ctx, ctxCancel := context.WithCancel(context.Background())
	pubsub, err := pubsub.NewGossipSub(
		ctx,
		host,
		pubsub.WithMessageSigning(true),
		pubsub.WithStrictSignatureVerification(true),
		pubsub.WithFloodPublish(true),
		pubsub.WithPeerExchange(true),
		pubsub.WithPeerOutboundQueueSize(viper.GetInt(CfgP2PPeerOutboundQueueSize)),
		pubsub.WithValidateQueueSize(viper.GetInt(CfgP2PValidateQueueSize)),
		pubsub.WithValidateThrottle(viper.GetInt(CfgP2PValidateThrottle)),
		pubsub.WithMessageIdFn(messageIdFn),
	)
	if err != nil {
		ctxCancel()
		_ = host.Close()
		return nil, fmt.Errorf("worker/common/p2p: failed to initialize libp2p gossipsub: %w", err)
	}

	chainContext, err := consensus.GetChainContext(ctx)
	if err != nil {
		ctxCancel()
		_ = host.Close()
		return nil, fmt.Errorf("worker/common/p2p: failed to get consensus chain context: %w", err)
	}

	p := &P2P{
		PeerManager:       newPeerManager(ctx, host, cg, consensus),
		ctxCancel:         ctxCancel,
		quitCh:            make(chan struct{}),
		chainContext:      chainContext,
		host:              host,
		pubsub:            pubsub,
		registerAddresses: registerAddresses,
		topics:            make(map[common.Namespace]map[TopicKind]*topicHandler),
		logger:            logging.GetLogger("worker/common/p2p"),
	}

	p.logger.Info("p2p host initialized",
		"address", fmt.Sprintf("%+v", host.Addrs()),
	)

	return p, nil
}
