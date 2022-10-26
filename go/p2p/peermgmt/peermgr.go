package peermgmt

import (
	"context"
	"math/rand"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

const (
	// monitorInterval is the time interval between checks for whether more peers have to be
	// connected.
	monitorInterval = time.Second
)

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
) *PeerManager {
	l := logging.GetLogger("p2p/peer-manager")
	cm := h.ConnManager()

	return &PeerManager{
		logger:    l,
		host:      h,
		pubsub:    ps,
		registry:  newPeerRegistry(consensus, chainContext),
		connector: newPeerConnector(h, g),
		tagger:    newPeerTagger(cm),
		backup:    newPeerstoreBackup(h, cs),
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

	// Connect to peers from the backup in the background.
	var wg sync.WaitGroup
	defer wg.Wait()

	restoreCtx, restoreCancel := context.WithCancel(ctx)
	defer restoreCancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		m.backup.restore(restoreCtx, m.connector)
	}()

	// Main loop.
	monitorTicker := time.NewTicker(monitorInterval)

	for {
		select {
		case <-monitorTicker.C:
			m.connectRegisteredPeers(ctx)

		case <-ctx.Done():
			return
		}
	}
}

// connectRegisteredPeers checks if there are enough connections to registered peers
// for any protocol and topic and connects to new ones if needed.
func (m *PeerManager) connectRegisteredPeers(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	for p, d := range m.protocols {
		registered := m.registry.protocolPeersInfo(p)
		connected := m.protocolPeers(p)
		limit := d.min

		wg.Add(1)
		go func() {
			defer wg.Done()
			m.connect(ctx, registered, connected, limit)
		}()
	}

	for t, d := range m.topics {
		registered := m.registry.topicPeersInfo(t)
		connected := m.topicPeers(t)
		limit := d.min

		wg.Add(1)
		go func() {
			defer wg.Done()
			m.connect(ctx, registered, connected, limit)
		}()
	}
}

func (m *PeerManager) protocolPeers(p core.ProtocolID) map[core.PeerID]struct{} {
	peers := make(map[core.PeerID]struct{})
	for _, peer := range m.host.Network().Peers() {
		if m.supportsProtocol(peer, p) {
			peers[peer] = struct{}{}
		}
	}

	return peers
}

func (m *PeerManager) topicPeers(topic string) map[core.PeerID]struct{} {
	peers := make(map[core.PeerID]struct{})
	for _, peer := range m.pubsub.ListPeers(topic) {
		peers[peer] = struct{}{}
	}

	return peers
}

func (m *PeerManager) connect(ctx context.Context, addrs []*peer.AddrInfo, connected map[core.PeerID]struct{}, max int) {
	// Put disconnected peers to the front, so that we don't need to create another array.
	next := 0
	last := len(addrs) - 1
	for next <= last {
		if _, ok := connected[addrs[next].ID]; !ok {
			next++
			continue
		}
		addrs[next], addrs[last] = addrs[last], addrs[next]
		last--
		max--
	}

	// Shuffle disconnected and connect to few of them.
	disc := addrs[0 : last+1]

	rand.Shuffle(len(disc), func(i, j int) {
		disc[i], disc[j] = disc[j], disc[i]
	})

	m.connector.connectMany(ctx, disc, max)
}

func (m *PeerManager) supportsProtocol(p core.PeerID, protocol core.ProtocolID) bool {
	supported, err := m.host.Peerstore().FirstSupportedProtocol(p, string(protocol))
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
