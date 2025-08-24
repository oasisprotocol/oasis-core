package peermgmt

import (
	"context"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

type peerRegistry struct {
	mu sync.Mutex

	peers         map[core.PeerID]peer.AddrInfo
	protocolPeers map[core.ProtocolID]map[core.PeerID]struct{}
	topicPeers    map[string]map[core.PeerID]struct{}

	chainContext string
	consensusCh  chan consensus.Service

	initCh   chan struct{}
	initOnce sync.Once

	startOne cmSync.One

	logger *logging.Logger
}

func newPeerRegistry() *peerRegistry {
	logger := logging.GetLogger("p2p/peer-manager/registry")

	return &peerRegistry{
		peers:         make(map[core.PeerID]peer.AddrInfo),
		protocolPeers: make(map[core.ProtocolID]map[core.PeerID]struct{}),
		topicPeers:    make(map[string]map[core.PeerID]struct{}),
		consensusCh:   make(chan consensus.Service, 1),
		initCh:        make(chan struct{}),
		startOne:      cmSync.NewOne(),
		logger:        logger,
	}
}

// Initialized implements api.PeerRegistry.
func (r *peerRegistry) Initialized() <-chan struct{} {
	return r.initCh
}

// NumPeers implements api.PeerRegistry.
func (r *peerRegistry) NumPeers() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.peers)
}

// RegisterConsensus implements api.PeerRegistry.
func (r *peerRegistry) RegisterConsensus(chainContext string, consensus consensus.Service) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if chainContext == "" {
		return fmt.Errorf("invalid chain context")
	}

	if r.chainContext != "" {
		return fmt.Errorf("consensus already registered")
	}

	r.chainContext = chainContext
	r.consensusCh <- consensus

	return nil
}

func (r *peerRegistry) findProtocolPeers(ctx context.Context, p core.ProtocolID) <-chan peer.AddrInfo {
	getPeerMap := func() map[peer.ID]struct{} {
		return r.protocolPeers[p]
	}

	return r.findPeers(ctx, getPeerMap)
}

func (r *peerRegistry) findTopicPeers(ctx context.Context, topic string) <-chan peer.AddrInfo {
	getPeerMap := func() map[peer.ID]struct{} {
		return r.topicPeers[topic]
	}

	return r.findPeers(ctx, getPeerMap)
}

func (r *peerRegistry) findPeers(ctx context.Context, getPeerMap func() map[peer.ID]struct{}) <-chan peer.AddrInfo {
	peerCh := make(chan peer.AddrInfo)

	r.mu.Lock()
	defer r.mu.Unlock()

	peerMap := getPeerMap()
	peers := make([]peer.ID, 0, len(peerMap))
	for peer := range peerMap {
		peers = append(peers, peer)
	}

	go func() {
		defer close(peerCh)

		for _, peer := range peers {
			r.mu.Lock()
			addr, ok := r.peers[peer]
			r.mu.Unlock()

			if !ok {
				continue
			}

			select {
			case peerCh <- addr:
			case <-ctx.Done():
				return
			}
		}
	}()

	return peerCh
}

// start starts watching the registry for node changes and assigns nodes to protocols and topics
// according to their roles.
func (r *peerRegistry) start() {
	r.startOne.TryStart(r.watch)
}

// stop stops watching the registry.
func (r *peerRegistry) stop() {
	r.startOne.TryStop()
}

func (r *peerRegistry) watch(ctx context.Context) {
	// Wait for consensus to be registered.
	var consensus consensus.Service
	select {
	case consensus = <-r.consensusCh:
	case <-ctx.Done():
		return
	}

	// Wait for consensus sync before proceeding.
	select {
	case <-consensus.Synced():
	case <-ctx.Done():
		return
	}

	// Listen to nodes on epoch transitions.
	nodeListCh, nlSub, err := consensus.Registry().WatchNodeList(ctx)
	if err != nil {
		r.logger.Error("failed to watch registry for node list changes",
			"err", err,
		)
		return
	}
	defer nlSub.Close()

	// Listen to nodes on node events.
	nodeCh, nSub, err := consensus.Registry().WatchNodes(ctx)
	if err != nil {
		r.logger.Error("failed to watch registry for node changes",
			"err", err,
		)
		return
	}
	defer nSub.Close()

	for {
		select {
		case nodes := <-nodeListCh:
			r.clearNodes()
			r.handleNodes(nodes.Nodes)

		case nodeEv := <-nodeCh:
			if nodeEv.IsRegistration {
				r.handleNodes([]*node.Node{nodeEv.Node})
			}

		case <-ctx.Done():
			return
		}
	}
}

// clearNodes clears the protocols and topics supported by the observed nodes.
func (r *peerRegistry) clearNodes() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear current state.
	r.peers = make(map[core.PeerID]peer.AddrInfo)
	r.protocolPeers = make(map[core.ProtocolID]map[core.PeerID]struct{})
	r.topicPeers = make(map[string]map[core.PeerID]struct{})
}

// handleNodes updates protocols and topics supported by the given nodes and resets them if needed.
func (r *peerRegistry) handleNodes(nodes []*node.Node) {
	defer r.initOnce.Do(func() {
		close(r.initCh)
	})

	type peerData struct {
		info      peer.AddrInfo
		protocols map[core.ProtocolID]struct{}
		topics    map[string]struct{}
	}

	peers := make(map[core.PeerID]*peerData)
	for _, n := range nodes {
		info, err := p2pInfoToAddrInfo(&n.P2P)
		if err != nil {
			r.logger.Error("failed to convert node to node info",
				"err", err,
				"node_id", n.ID,
			)
			continue
		}

		protocols, topics := r.inspectNode(n)

		peers[info.ID] = &peerData{*info, protocols, topics}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Add/update new peers.
	for p, data := range peers {
		// Remove old protocols/topics.
		for _, peers := range r.protocolPeers {
			delete(peers, p)
		}
		for _, peers := range r.topicPeers {
			delete(peers, p)
		}

		// Add new ones.
		for protocol := range data.protocols {
			peers, ok := r.protocolPeers[protocol]
			if !ok {
				peers = make(map[core.PeerID]struct{})
				r.protocolPeers[protocol] = peers
			}
			peers[p] = struct{}{}
		}
		for topic := range data.topics {
			peers, ok := r.topicPeers[topic]
			if !ok {
				peers = make(map[core.PeerID]struct{})
				r.topicPeers[topic] = peers
			}
			peers[p] = struct{}{}
		}

		// Update the address, as it might have changed.
		r.peers[p] = data.info
	}
}

func (r *peerRegistry) inspectNode(n *node.Node) (map[core.ProtocolID]struct{}, map[string]struct{}) {
	pMap := make(map[core.ProtocolID]struct{})
	tMap := make(map[string]struct{})

	nodeHandlers.RLock()
	defer nodeHandlers.RUnlock()

	for _, h := range nodeHandlers.l {
		for _, p := range h.Protocols(n, r.chainContext) {
			pMap[p] = struct{}{}
		}
		for _, t := range h.Topics(n, r.chainContext) {
			tMap[t] = struct{}{}
		}
	}

	return pMap, tMap
}

func p2pInfoToAddrInfo(pi *node.P2PInfo) (*peer.AddrInfo, error) {
	var (
		ai  peer.AddrInfo
		err error
	)
	if ai.ID, err = api.PublicKeyToPeerID(pi.ID); err != nil {
		return nil, fmt.Errorf("failed to extract public key from node P2P ID: %w", err)
	}
	for _, nodeAddr := range pi.Addresses {
		addr, err := manet.FromNetAddr(nodeAddr.ToTCPAddr())
		if err != nil {
			return nil, fmt.Errorf("failed to convert address to libp2p format: %w", err)
		}
		ai.Addrs = append(ai.Addrs, addr)
	}

	return &ai, nil
}
