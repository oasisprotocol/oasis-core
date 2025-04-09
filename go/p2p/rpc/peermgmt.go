package rpc

import (
	cryptorand "crypto/rand"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

const (
	SuccessConnManagerPeerTagValue = 20
	ShuffledBestPeerCount          = 5

	// newPeerScoreMultiplier is the score multiplier for new peers for which we don't yet have any
	// historical measurements.
	newPeerScoreMultiplier = 0.9
)

// Inverse alpha (1/alpha) values for computing the exponential moving average of latencies used for
// peer scoring. Split into peer-local and global EMAs.
const (
	peerInvAlpha   = 10
	globalInvAlpha = 25
)

// BestPeersOptions are per-call options.
type BestPeersOptions struct {
	limitPeers []core.PeerID
}

// NewBestPeersOptions creates options using default and given values.
func NewBestPeersOptions(opts ...BestPeersOption) *BestPeersOptions {
	bpo := BestPeersOptions{}
	for _, opt := range opts {
		opt(&bpo)
	}
	return &bpo
}

// BestPeersOption is a per-call option setter.
type BestPeersOption func(opts *BestPeersOptions)

// WithLimitPeers configures the peers that the call should be limited to.
func WithLimitPeers(peers []core.PeerID) BestPeersOption {
	return func(opts *BestPeersOptions) {
		opts.limitPeers = peers
	}
}

// PeerManager is an interface for keeping track of peer statistics in order to guide peer selection
// when performing RPC requests.
type PeerManager interface {
	// AddPeer tries to add the given peer to the peer manager.
	//
	// Peer is only added in case it supports the specified protocol.
	AddPeer(peerID core.PeerID)

	// RemovePeer unconditionally removes the peer from the peer manager.
	RemovePeer(peerID core.PeerID)

	// RecordSuccess records a successful protocol interaction with the given peer.
	RecordSuccess(peerID core.PeerID, latency time.Duration)

	// RecordFailure records an unsuccessful protocol interaction with the given peer.
	RecordFailure(peerID core.PeerID, latency time.Duration)

	// RecordBadPeer records a malicious protocol interaction with the given peer.
	//
	// The peer will be ignored during peer selection.
	RecordBadPeer(peerID core.PeerID)

	// GetBestPeers returns a set of peers sorted by the probability that they will be able to
	// answer our requests the fastest with some randomization.
	GetBestPeers(opts ...BestPeersOption) []core.PeerID

	// WatchUpdates returns a channel that produces a stream of messages on peer updates.
	WatchUpdates() (<-chan *PeerUpdate, pubsub.ClosableSubscription, error)
}

// PeerUpdate is a peer update event.
type PeerUpdate struct {
	ID core.PeerID

	PeerAdded   *PeerAdded
	PeerRemoved *PeerRemoved
}

// PeerAdded is an event emitted when a new peer is added.
type PeerAdded struct{}

// PeerRemoved is an event emitted when a peer is removed.
type PeerRemoved struct {
	// BadPeer indicates that the peer was removed due to being recorded as a bad peer.
	BadPeer bool
}

type peerStats struct {
	successes         int
	failures          int
	avgRequestLatency time.Duration
}

// getScore returns the peer score (lower is better).
func (ps *peerStats) getScore(avgRequestLatency time.Duration) float64 {
	if ps.successes+ps.failures > 0 {
		// We have some history for this peer.
		failRate := float64(ps.failures) / float64(ps.failures+ps.successes)
		return float64(ps.avgRequestLatency) + failRate*float64(avgRequestLatency)
	}
	return float64(avgRequestLatency) * newPeerScoreMultiplier
}

func (ps *peerStats) recordLatency(latency time.Duration) {
	if ps.avgRequestLatency == 0 {
		ps.avgRequestLatency = latency
	} else {
		// Compute exponential moving average.
		delta := (latency - ps.avgRequestLatency) / peerInvAlpha
		ps.avgRequestLatency += delta
	}
}

type peerManager struct {
	sync.RWMutex

	p2p        P2P
	host       core.Host
	protocolID protocol.ID

	peerUpdatesNotifier *pubsub.Broker
	peers               map[core.PeerID]*peerStats
	ignoredPeers        map[core.PeerID]bool

	avgRequestLatency time.Duration

	logger *logging.Logger
}

func (mgr *peerManager) AddPeer(peerID core.PeerID) {
	mgr.Lock()
	defer mgr.Unlock()

	// Do not re-add existing peers.
	if _, exists := mgr.peers[peerID]; exists {
		return
	}
	// Do not re-add ignored peers.
	if mgr.ignoredPeers[peerID] {
		return
	}
	mgr.peers[peerID] = &peerStats{}

	mgr.logger.Debug("added new peer",
		"peer_id", peerID,
		"num_peers", len(mgr.peers),
	)
	mgr.peerUpdatesNotifier.Broadcast(&PeerUpdate{ID: peerID, PeerAdded: &PeerAdded{}})
}

func (mgr *peerManager) RemovePeer(peerID core.PeerID) {
	mgr.Lock()
	defer mgr.Unlock()

	if _, exists := mgr.peers[peerID]; !exists {
		return
	}

	delete(mgr.peers, peerID)

	mgr.logger.Debug("removed peer",
		"peer_id", peerID,
		"num_peers", len(mgr.peers),
	)
	mgr.peerUpdatesNotifier.Broadcast(&PeerUpdate{ID: peerID, PeerRemoved: &PeerRemoved{}})
}

func (mgr *peerManager) RecordSuccess(peerID core.PeerID, latency time.Duration) {
	mgr.Lock()
	defer mgr.Unlock()

	ps, exists := mgr.peers[peerID]
	if !exists {
		return
	}
	ps.successes++
	ps.recordLatency(latency)

	// Update global stats.
	if mgr.avgRequestLatency == 0 {
		mgr.avgRequestLatency = latency
	} else {
		// Compute exponential moving average.
		delta := (latency - mgr.avgRequestLatency) / globalInvAlpha
		mgr.avgRequestLatency += delta
	}

	mgr.host.ConnManager().TagPeer(peerID, string(mgr.protocolID), SuccessConnManagerPeerTagValue)
}

func (mgr *peerManager) RecordFailure(peerID core.PeerID, latency time.Duration) {
	mgr.Lock()
	defer mgr.Unlock()

	ps, exists := mgr.peers[peerID]
	if !exists {
		return
	}
	ps.failures++
	ps.recordLatency(latency)
}

func (mgr *peerManager) RecordBadPeer(peerID core.PeerID) {
	mgr.Lock()
	defer mgr.Unlock()

	mgr.p2p.BlockPeer(peerID)
	mgr.ignoredPeers[peerID] = true

	if _, exists := mgr.peers[peerID]; !exists {
		return
	}

	delete(mgr.peers, peerID)
	mgr.peerUpdatesNotifier.Broadcast(&PeerUpdate{ID: peerID, PeerRemoved: &PeerRemoved{BadPeer: true}})
}

func (mgr *peerManager) WatchUpdates() (<-chan *PeerUpdate, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *PeerUpdate)
	sub := mgr.peerUpdatesNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (mgr *peerManager) GetBestPeers(opts ...BestPeersOption) []core.PeerID {
	mgr.Lock()
	defer mgr.Unlock()

	o := NewBestPeersOptions(opts...)

	// Start by including all peers that are in the limited set, if given.
	peers := make([]core.PeerID, 0, len(mgr.peers))
	switch len(o.limitPeers) {
	case 0:
		// Add all known peers.
		for peer := range mgr.peers {
			peers = append(peers, peer)
		}
	default:
		// Keep peers from the limited set only.
		for _, peer := range o.limitPeers {
			if _, ok := mgr.peers[peer]; !ok {
				continue
			}
			peers = append(peers, peer)
		}
	}

	// Sort peers by success rate and latency.
	sort.Slice(peers, func(i, j int) bool {
		pi := mgr.peers[peers[i]]
		pj := mgr.peers[peers[j]]

		scoreI := pi.getScore(mgr.avgRequestLatency)
		scoreJ := pj.getScore(mgr.avgRequestLatency)

		return scoreI < scoreJ
	})

	// Randomize the first few peers.
	shufflePeerCount := ShuffledBestPeerCount
	if len(peers) < shufflePeerCount {
		shufflePeerCount = len(peers)
	}
	bestPeers := peers[:shufflePeerCount]

	rng := rand.New(mathrand.New(cryptorand.Reader))
	rng.Shuffle(len(bestPeers), func(i, j int) {
		bestPeers[i], bestPeers[j] = bestPeers[j], bestPeers[i]
	})

	return peers
}

func (mgr *peerManager) peerProtocolWatcher() {
	// Subscribe to peer protocol updates.
	sub, err := mgr.host.EventBus().Subscribe([]any{
		new(event.EvtPeerIdentificationCompleted),
		new(event.EvtPeerProtocolsUpdated),
	})
	if err != nil {
		mgr.logger.Error("failed to subscribe to peer protocol updates",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Subscribe to peer disconnection events.
	mgr.host.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(net network.Network, conn network.Conn) {
			peer := conn.RemotePeer()
			if len(net.ConnsToPeer(peer)) == 0 {
				// If we don't have any more connections to a given peer, remove it.
				mgr.RemovePeer(peer)
			}
		},
	})

	// Now that we have subscribed, make sure to process any peers that are already there.
	for _, peerID := range mgr.host.Network().Peers() {
		protocols, err := mgr.host.Peerstore().GetProtocols(peerID)
		if err != nil {
			mgr.logger.Error("failed to get peer's protocols",
				"err", err,
				"peer_id", peerID,
			)
			continue
		}

		for _, p := range protocols {
			if p == mgr.protocolID {
				mgr.AddPeer(peerID)
			}
		}
	}

	for ev := range sub.Out() {
		switch evt := ev.(type) {
		case event.EvtPeerIdentificationCompleted:
			// New peer has completed the identification protocol handshake.
			protocols, err := mgr.host.Peerstore().GetProtocols(evt.Peer)
			if err != nil {
				mgr.logger.Error("failed to get peer's protocols",
					"err", err,
					"peer_id", evt.Peer,
				)
				continue
			}

			for _, p := range protocols {
				if p == mgr.protocolID {
					mgr.AddPeer(evt.Peer)
				}
			}
		case event.EvtPeerProtocolsUpdated:
			// Peer's protocols updated.
			for _, p := range evt.Added {
				if p == mgr.protocolID {
					mgr.AddPeer(evt.Peer)
				}
			}

			for _, p := range evt.Removed {
				if p == mgr.protocolID {
					mgr.RemovePeer(evt.Peer)
				}
			}
		}
	}
}

// NewPeerManager creates a new peer manager for the given protocol.
func NewPeerManager(p2p P2P, protocolID protocol.ID) PeerManager {
	if p2p.Host() == nil {
		// No P2P service, use the no-op peer manager.
		return &nopPeerManager{}
	}

	mgr := &peerManager{
		p2p:                 p2p,
		host:                p2p.Host(),
		protocolID:          protocolID,
		peerUpdatesNotifier: pubsub.NewBroker(false),
		peers:               make(map[core.PeerID]*peerStats),
		ignoredPeers:        make(map[core.PeerID]bool),
		logger: logging.GetLogger("p2p/rpc/peermgr").With(
			"protocol_id", protocolID,
		),
	}
	go mgr.peerProtocolWatcher()

	return mgr
}
