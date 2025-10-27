// Package p2p implements the worker committee gossip network.
package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/conngater"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tuplehash"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/discovery/bootstrap"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

const (
	// peersHighWatermarkDelta specifies how many peers after the maximum peer count is reached we
	// ask the connection manager to start pruning peers.
	peersHighWatermarkDelta = 30

	// seenMessagesTTL is the amount of time pubsub messages will be remembered as seen and any
	// duplicates will be dropped before propagation.
	seenMessagesTTL = 120 * time.Second

	// minTopicPeers is the minimum number of peers from the registry we want to have connected
	// for a topic.
	minTopicPeers = 10

	// totalTopicPeers is the number of peers we want to have connected for a topic.
	totalTopicPeers = 20
)

// messageIdContext is the domain separation context for computing message identifier hashes.
var messageIdContext = []byte("oasis-core/p2p: message id") // nolint: revive

var allowUnroutableAddresses bool

// DebugForceAllowUnroutableAddresses allows unroutable addresses.
func DebugForceAllowUnroutableAddresses() {
	allowUnroutableAddresses = true
}

// p2p is a peer-to-peer node using libp2p.
type p2p struct {
	sync.RWMutex

	ctx             context.Context
	ctxCancel       context.CancelFunc
	quitCh          chan struct{}
	metricsClosedCh chan struct{}

	chainContext string
	signer       signature.Signer

	host   core.Host
	pubsub *pubsub.PubSub

	gater   *conngater.BasicConnectionGater
	peerMgr *peermgmt.PeerManager

	registerAddresses []multiaddr.Multiaddr
	topics            map[string]*topicHandler

	logger *logging.Logger
}

// Implements api.Service.
func (p *p2p) Cleanup() {
}

// Implements api.Service.
func (p *p2p) Name() string {
	return "worker p2p"
}

// Implements api.Service.
func (p *p2p) Start() error {
	// Unfortunately, we cannot start the host as libp2p starts everything on construction.
	// However, we can start everything else.
	p.peerMgr.Start()
	go p.metricsWorker()

	return nil
}

// Implements api.Service.
func (p *p2p) Stop() {
	defer close(p.quitCh)

	p.ctxCancel()

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Go(p.peerMgr.Stop) // This blocks until the manager stops.
	wg.Go(func() {
		_ = p.host.Close // This blocks until the host stops.
	})
	wg.Go(func() {
		<-p.metricsClosedCh
	})
}

// Implements api.Service.
func (p *p2p) Quit() <-chan struct{} {
	return p.quitCh
}

// Implements api.Service.
func (p *p2p) GetStatus() *api.Status {
	protocols := make(map[core.ProtocolID]int)
	for _, protocol := range p.peerMgr.Protocols() {
		protocols[protocol] = p.peerMgr.NumProtocolPeers(protocol)
	}

	topics := make(map[string]int)
	for _, topic := range p.peerMgr.Topics() {
		topics[topic] = p.peerMgr.NumTopicPeers(topic)
	}

	return &api.Status{
		PubKey:         p.signer.Public(),
		PeerID:         p.host.ID(),
		Addresses:      p.Addresses(),
		NumPeers:       len(p.host.Network().Peers()),
		NumConnections: len(p.host.Network().Conns()),
		Protocols:      protocols,
		Topics:         topics,
	}
}

// Implements api.Service.
func (p *p2p) Addresses() []node.Address {
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

// Implements api.Service.
func (p *p2p) Peers(runtimeID common.Namespace) []string {
	allPeers := p.pubsub.ListPeers(protocol.NewTopicKindCommitteeID(p.chainContext, runtimeID))
	allPeers = append(allPeers, p.pubsub.ListPeers(protocol.NewTopicKindTxID(p.chainContext, runtimeID))...)

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

		info := peer.AddrInfo{
			ID:    peerID,
			Addrs: addrs[:1],
		}
		peers = append(peers, api.AddrInfoToString(info)[0])
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

// Implements api.Service.
func (p *p2p) Publish(_ context.Context, topic string, msg any) {
	rawMsg := cbor.Marshal(msg)

	p.RLock()
	defer p.RUnlock()

	h := p.topics[topic]
	if h == nil {
		p.logger.Error("attempted to publish message for unsupported topic",
			"topic", topic,
		)
		return
	}

	if err := h.tryPublishing(rawMsg); err != nil {
		h.logger.Error("failed to publish message to the network",
			"err", err,
		)
	}

	p.logger.Debug("published message",
		"topic", topic,
	)
}

// Implements api.Service.
func (p *p2p) RegisterHandler(topic string, handler api.Handler) {
	protocol.ValidateTopicID(topic)

	p.Lock()
	defer p.Unlock()

	if _, ok := p.topics[topic]; ok {
		panic(fmt.Sprintf("p2p: handler for topic '%s' already registered", topic))
	}

	h, err := newTopicHandler(p, topic, handler)
	if err != nil {
		panic(fmt.Sprintf("p2p: failed to initialize topic handler: %s", err))
	}
	p.topics[topic] = h
	_ = p.pubsub.RegisterTopicValidator(
		topic,
		h.topicMessageValidator,
		pubsub.WithValidatorConcurrency(config.GlobalConfig.P2P.Gossipsub.ValidateConcurrency),
	)

	p.logger.Debug("registered new topic handler",
		"topic", topic,
	)

	p.peerMgr.TrackTopicPeers(topic, minTopicPeers, totalTopicPeers)
	p.peerMgr.AdvertiseTopic(topic)
}

// Implements api.Service.
func (p *p2p) BlockPeer(peerID core.PeerID) {
	p.logger.Warn("blocking peer",
		"peer_id", peerID,
	)

	p.pubsub.BlacklistPeer(peerID)
	_ = p.gater.BlockPeer(peerID)
	_ = p.host.Network().ClosePeer(peerID)
}

// Implements api.Service.
func (p *p2p) RegisterProtocol(pid core.ProtocolID, minPeers int, totalPeers int) {
	p.peerMgr.TrackProtocolPeers(pid, minPeers, totalPeers)
}

// Implements api.Service.
func (p *p2p) Host() core.Host {
	return p.host
}

// Implements api.Service.
func (p *p2p) PeerManager() api.PeerManager {
	return p.peerMgr
}

// Implements api.Service.
func (p *p2p) RegisterProtocolServer(srv rpc.Server) {
	protocol.ValidateProtocolID(srv.Protocol())

	p.host.SetStreamHandler(srv.Protocol(), srv.HandleStream)

	p.peerMgr.AdvertiseProtocol(srv.Protocol())

	p.logger.Info("registered protocol server",
		"protocol_id", srv.Protocol(),
	)
}

// Implements api.Service.
func (p *p2p) GetMinRepublishInterval() time.Duration {
	return seenMessagesTTL + 5*time.Second
}

func messageIdFn(pmsg *pb.Message) string { // nolint: revive
	// id := TupleHash[messageIdContext](topic, data)
	h := tuplehash.New256(32, messageIdContext)
	_, _ = h.Write([]byte(pmsg.GetTopic()))
	_, _ = h.Write(pmsg.Data)
	return string(h.Sum(nil))
}

// New creates a new P2P node.
func New(identity *identity.Identity, chainContext string, store *persistent.CommonStore) (api.Service, error) {
	var cfg Config
	if err := cfg.Load(); err != nil {
		return nil, fmt.Errorf("p2p: failed to load peer config: %w", err)
	}

	// Create the P2P host.
	cfg.HostConfig.Signer = identity.P2PSigner
	host, cg, err := NewHost(&cfg.HostConfig)
	if err != nil {
		return nil, fmt.Errorf("p2p: failed to initialize libp2p host: %w", err)
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
		pubsub.WithPeerOutboundQueueSize(cfg.PeerOutboundQueueSize),
		pubsub.WithValidateQueueSize(cfg.ValidateQueueSize),
		pubsub.WithValidateThrottle(cfg.ValidateThrottle),
		pubsub.WithMessageIdFn(messageIdFn),
		pubsub.WithDirectPeers(cfg.PersistentPeers),
		pubsub.WithSeenMessagesTTL(seenMessagesTTL),
	)
	if err != nil {
		ctxCancel()
		_ = host.Close()
		return nil, fmt.Errorf("p2p: failed to initialize libp2p gossipsub: %w", err)
	}

	// Initialize the peer manager.
	opts := make([]peermgmt.PeerManagerOption, 0, 1)

	if cfg.BootstrapDiscoveryConfig.Enable {
		seeds := make([]discovery.Discovery, 0, len(cfg.Seeds))
		for i := range cfg.Seeds {
			seed := bootstrap.NewClient(host, cfg.Seeds[i],
				bootstrap.WithRetentionPeriod(cfg.RetentionPeriod),
			)
			seeds = append(seeds, seed)
		}
		opts = append(opts, peermgmt.WithBootstrapDiscovery(seeds))
	}

	mgr := peermgmt.NewPeerManager(host, cg, pubsub, store, opts...)

	// Initialize the logger.
	logger := logging.GetLogger("p2p")

	logger.Info("p2p host initialized",
		"address", fmt.Sprintf("%+v", host.Addrs()),
	)

	if len(cfg.BlockedPeers) > 0 {
		logger.Info("p2p blacklist initialized",
			"num_blocked_peers", len(cfg.BlockedPeers),
		)
	}

	return &p2p{
		ctx:               ctx,
		ctxCancel:         ctxCancel,
		quitCh:            make(chan struct{}),
		metricsClosedCh:   make(chan struct{}),
		chainContext:      chainContext,
		signer:            identity.P2PSigner,
		host:              host,
		gater:             cg,
		peerMgr:           mgr,
		pubsub:            pubsub,
		registerAddresses: cfg.Addresses,
		topics:            make(map[string]*topicHandler),
		logger:            logger,
	}, nil
}

// Config describes a set of P2P settings for a peer.
type Config struct {
	Addresses []multiaddr.Multiaddr

	HostConfig
	GossipSubConfig
	BootstrapDiscoveryConfig
}

// Load loads P2P configuration.
func (cfg *Config) Load() error {
	rawAddresses, err := configparser.ParseAddressList(config.GlobalConfig.P2P.Registration.Addresses)
	if err != nil {
		return fmt.Errorf("failed to parse address list: %w", err)
	}
	var addresses []multiaddr.Multiaddr
	for _, addr := range rawAddresses {
		var mAddr multiaddr.Multiaddr
		mAddr, err = manet.FromNetAddr(addr.ToTCPAddr())
		if err != nil {
			return fmt.Errorf("failed to convert address to multiaddress: %w", err)
		}
		addresses = append(addresses, mAddr)
	}

	var hostCfg HostConfig
	if err := hostCfg.Load(); err != nil {
		return fmt.Errorf("failed to load host config: %w", err)
	}

	var gossipSubCfg GossipSubConfig
	if err := gossipSubCfg.Load(); err != nil {
		return fmt.Errorf("failed to load gossipsub config: %w", err)
	}

	var bootstrapCfg BootstrapDiscoveryConfig
	if err := bootstrapCfg.Load(); err != nil {
		return fmt.Errorf("failed to load bootstrap config: %w", err)
	}

	cfg.Addresses = addresses
	cfg.HostConfig = hostCfg
	cfg.GossipSubConfig = gossipSubCfg
	cfg.BootstrapDiscoveryConfig = bootstrapCfg

	return nil
}

// GossipSubConfig describes a set of settings for a gossip pubsub.
type GossipSubConfig struct {
	// XXX: Main config has int64, but here just int -- investigate.
	PeerOutboundQueueSize int
	ValidateQueueSize     int
	ValidateThrottle      int

	PersistentPeers []peer.AddrInfo
}

// Load loads gossipsub configuration.
func (cfg *GossipSubConfig) Load() error {
	persistentPeers, err := api.AddrInfosFromConsensusAddrs(config.GlobalConfig.P2P.ConnectionManager.PersistentPeers)
	if err != nil {
		return fmt.Errorf("failed to convert persistent peers' addresses: %w", err)
	}

	cfg.PeerOutboundQueueSize = config.GlobalConfig.P2P.Gossipsub.PeerOutboundQueueSize
	cfg.ValidateQueueSize = config.GlobalConfig.P2P.Gossipsub.ValidateQueueSize
	cfg.ValidateThrottle = config.GlobalConfig.P2P.Gossipsub.ValidateThrottle
	cfg.PersistentPeers = persistentPeers

	return nil
}

// BootstrapDiscoveryConfig describes a set of settings for a discovery.
type BootstrapDiscoveryConfig struct {
	Enable          bool
	Seeds           []peer.AddrInfo
	RetentionPeriod time.Duration
}

// Load loads bootstrap discovery configuration.
func (cfg *BootstrapDiscoveryConfig) Load() error {
	seeds, err := api.AddrInfosFromConsensusAddrs(config.GlobalConfig.P2P.Seeds)
	if err != nil {
		return fmt.Errorf("failed to convert seeds' addresses: %w", err)
	}

	cfg.Seeds = seeds
	cfg.Enable = config.GlobalConfig.P2P.Discovery.Bootstrap.Enable
	cfg.RetentionPeriod = config.GlobalConfig.P2P.Discovery.Bootstrap.RetentionPeriod

	return nil
}
