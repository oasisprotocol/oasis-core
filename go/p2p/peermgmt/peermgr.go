package peermgmt

import (
	"context"
	"math/rand"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/backup"
)

const (
	// monitorInterval is the time interval between checks for whether more peers have to be
	// connected.
	monitorInterval = time.Second

	// maxRestoredPeers is the maximum number of peers connected on startup from the backup.
	maxRestoredPeers = 100
)

// PeerManagerOptions are peer manager options.
type PeerManagerOptions struct {
	seeds []discovery.Discovery
}

// PeerManagerOption is a peer manager option setter.
type PeerManagerOption func(opts *PeerManagerOptions)

// WithBootstrapDiscovery configures bootstrap discovery.
func WithBootstrapDiscovery(seeds []discovery.Discovery) PeerManagerOption {
	return func(opts *PeerManagerOptions) {
		opts.seeds = seeds
	}
}

type watermark struct {
	// min is the minimum number of peers from the registry we want to have connected.
	min int

	// total is the number of peers we want to have connected.
	total int
}

// PeerManager tracks and manages peers that support registered protocols and topics.
//
// Peer manager's main responsibility is to keep sufficient number of peers from the registry and
// from the discovery connected to the host for any protocol and topic. If the number of connected
// peers is too low, the manager will try to connect to known peers or try to find new ones.
type PeerManager struct {
	logger *logging.Logger

	host   host.Host
	pubsub *pubsub.PubSub

	registry  *peerRegistry
	discovery *peerDiscovery
	connector *peerConnector
	tagger    *peerTagger
	backup    *peerstoreBackup

	mu        sync.RWMutex
	protocols map[core.ProtocolID]*watermark
	topics    map[string]*watermark

	startOne cmSync.One
}

// NewPeerManager creates a new peer manager.
func NewPeerManager(
	h host.Host,
	g connmgr.ConnectionGater,
	ps *pubsub.PubSub,
	consensus consensus.Backend,
	chainContext string,
	cs *persistent.CommonStore,
	opts ...PeerManagerOption,
) *PeerManager {
	pmo := PeerManagerOptions{}
	for _, opt := range opts {
		opt(&pmo)
	}

	l := logging.GetLogger("p2p/peer-manager")
	cm := h.ConnManager()
	cstore := backup.NewCommonStoreBackend(cs, peerstoreBucketName, peerstoreBucketKey)

	return &PeerManager{
		logger:    l,
		host:      h,
		pubsub:    ps,
		registry:  newPeerRegistry(consensus, chainContext),
		connector: newPeerConnector(h, g),
		tagger:    newPeerTagger(cm),
		backup:    newPeerstoreBackup(h.Peerstore(), cstore),
		discovery: newPeerDiscovery(pmo.seeds),
		protocols: make(map[core.ProtocolID]*watermark),
		topics:    make(map[string]*watermark),
		startOne:  cmSync.NewOne(),
	}
}

// PeerRegistry implements api.PeerManager.
func (m *PeerManager) PeerRegistry() api.PeerRegistry {
	return m.registry
}

// PeerTagger implements api.PeerManager.
func (m *PeerManager) PeerTagger() api.PeerTagger {
	return m.tagger
}

// Start starts the background services required for the peer manager to work.
func (m *PeerManager) Start() {
	m.startOne.TryStart(func(ctx context.Context) {
		go m.run(ctx)
	})
}

// Stop stops all background services. The method blocks until all services finish their work.
func (m *PeerManager) Stop() {
	m.startOne.TryStop()
}

// Protocols returns the ids of the registered protocols.
func (m *PeerManager) Protocols() []core.ProtocolID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	protocols := make([]core.ProtocolID, 0, len(m.protocols))
	for p := range m.protocols {
		protocols = append(protocols, p)
	}
	return protocols
}

// Topics returns the ids of the registered topics.
func (m *PeerManager) Topics() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	topics := make([]string, 0, len(m.topics))
	for t := range m.topics {
		topics = append(topics, t)
	}
	return topics
}

// NumProtocolPeers returns the number of connected peers that support the given protocol.
func (m *PeerManager) NumProtocolPeers(p core.ProtocolID) int {
	n := 0
	for _, peer := range m.host.Network().Peers() {
		if m.supportsProtocol(peer, p) {
			n++
		}
	}
	return n
}

// NumTopicPeers returns the number of connected peers that support the given topic.
func (m *PeerManager) NumTopicPeers(topic string) int {
	return len(m.pubsub.ListPeers(topic))
}

// RegisterProtocol starts tracking and managing peers that support the given protocol.
// If the protocol is already registered, its values are updated.
func (m *PeerManager) RegisterProtocol(p core.ProtocolID, min int, total int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if w, ok := m.protocols[p]; ok {
		w.min = min
		w.total = total

		m.logger.Debug("protocol updated",
			"protocol", p,
			"min", min,
			"total", total,
		)

		return
	}

	m.protocols[p] = &watermark{min, total}
	m.discovery.startAdvertising(string(p))

	m.logger.Debug("protocol registered",
		"protocol", p,
		"min", min,
		"total", total,
	)
}

// RegisterTopic starts tracking and managing peers that support the given topic.
// If the topic is already registered, its values are updated.
func (m *PeerManager) RegisterTopic(topic string, min int, total int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if data, ok := m.topics[topic]; ok {
		data.min = min
		data.total = total

		m.logger.Debug("topic updated",
			"topic", topic,
			"min", min,
			"total", total,
		)

		return
	}

	m.topics[topic] = &watermark{min, total}
	m.discovery.startAdvertising(topic)

	m.logger.Debug("topic registered",
		"topic", topic,
		"min", min,
		"total", total,
	)
}

// UnregisterProtocol stops managing peers that support the given protocol.
// If the protocol is not registered, this is a noop operation.
func (m *PeerManager) UnregisterProtocol(p core.ProtocolID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.protocols[p]; !ok {
		return
	}

	delete(m.protocols, p)
	m.discovery.stopAdvertising(string(p))

	m.logger.Debug("protocol unregistered",
		"protocol", p,
	)
}

// UnregisterTopic stops managing peers that support the given topic.
// If the topic is not registered, this is a noop operation.
func (m *PeerManager) UnregisterTopic(topic string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.topics[topic]; !ok {
		return
	}

	delete(m.topics, topic)
	m.discovery.stopAdvertising(topic)

	m.logger.Debug("topic unregistered",
		"topic", topic,
	)
}

func (m *PeerManager) run(ctx context.Context) {
	// Start background services.
	m.backup.start()
	defer m.backup.stop()

	m.registry.start()
	defer m.registry.stop()

	m.discovery.start()
	defer m.discovery.stop()

	// Connect to peers from the backup in the background.
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := m.backup.restore(ctx); err != nil {
			return
		}
		m.connectRestoredPeers(ctx)
	}()

	// Main loop.
	monitorTicker := time.NewTicker(monitorInterval)

	for {
		select {
		case <-monitorTicker.C:
			m.connectRegisteredPeers(ctx)
			m.connectDiscoveredPeers(ctx)

		case <-ctx.Done():
			return
		}
	}
}

// connectRestoredPeers connects to a random subset of peers that were restored from the backup
// and added to the peerstore.
func (m *PeerManager) connectRestoredPeers(ctx context.Context) {
	m.logger.Debug("connecting to restored peer")

	var wg sync.WaitGroup
	defer wg.Wait()

	doneCh := make(chan struct{})
	defer close(doneCh)

	peerCh := make(chan peer.AddrInfo)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(peerCh)

		store := m.host.Peerstore()
		peers := store.PeersWithAddrs()
		for _, i := range rand.Perm(len(peers)) {
			select {
			case peerCh <- store.PeerInfo(peers[i]):
			case <-doneCh:
				return
			}
		}
	}()

	m.connector.connectMany(ctx, peerCh, maxRestoredPeers)
}

// connectRegisteredPeers checks if there are enough connections to registered peers
// for any protocol and topic and connects to new ones if needed.
func (m *PeerManager) connectRegisteredPeers(ctx context.Context) {
	m.connectPeers(ctx, true)
}

// connectDiscoveredPeers checks if there are enough connections for any protocol and topic
// and connects to new ones if needed.
func (m *PeerManager) connectDiscoveredPeers(ctx context.Context) {
	m.connectPeers(ctx, false)
}

func (m *PeerManager) connectPeers(ctx context.Context, registered bool) {
	// At the end cancel all discoveries.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	defer wg.Wait()

	connectPeers := func(peerCh <-chan peer.AddrInfo, limit int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.connector.connectMany(ctx, peerCh, limit)
		}()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for p, d := range m.protocols {
		connected := m.NumProtocolPeers(p)

		switch registered {
		case true:
			if limit := d.min - connected; limit > 0 {
				peerCh := m.registry.findProtocolPeers(ctx, p)
				connectPeers(peerCh, limit)
			}
		default:
			if limit := d.total - connected; limit > 0 {
				peerCh := m.discovery.findPeers(ctx, string(p))
				connectPeers(peerCh, limit)
			}
		}
	}

	for t, d := range m.topics {
		connected := m.NumTopicPeers(t)

		switch registered {
		case true:
			if limit := d.min - connected; limit > 0 {
				peerCh := m.registry.findTopicPeers(ctx, t)
				connectPeers(peerCh, limit)
			}

		default:
			if limit := d.total - connected; limit > 0 {
				peerCh := m.discovery.findPeers(ctx, t)
				connectPeers(peerCh, limit)
			}
		}
	}
}

func (m *PeerManager) supportsProtocol(p core.PeerID, protocol core.ProtocolID) bool {
	supported, err := m.host.Peerstore().FirstSupportedProtocol(p, protocol)
	if err != nil {
		m.logger.Debug("cannot determine if the peer supports the protocol",
			"err", err,
			"peer_id", p,
			"protocol_id", protocol,
		)
		return false
	}

	return supported != ""
}
