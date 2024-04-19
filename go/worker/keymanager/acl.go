package keymanager

import (
	"sync"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
)

// RuntimeList is a thread-safe collection of unique runtime IDs.
type RuntimeList struct {
	mu sync.RWMutex

	runtimes map[common.Namespace]struct{} // Guarded by mutex.
}

// NewRuntimeList constructs an empty runtime list.
func NewRuntimeList() *RuntimeList {
	return &RuntimeList{
		runtimes: make(map[common.Namespace]struct{}),
	}
}

// Contains returns true if and only if the list contains the given runtime.
//
// A nil runtime list is considered empty and will always return false.
func (l *RuntimeList) Contains(runtimeID common.Namespace) bool {
	if l == nil {
		return false
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	_, ok := l.runtimes[runtimeID]
	return ok
}

// Add adds the given runtime to the list.
func (l *RuntimeList) Add(runtimeID common.Namespace) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.runtimes[runtimeID] = struct{}{}
}

// Delete removes the given runtime from the list.
//
// If the runtime list is nil or there is no such element, this function is a no-op.
func (l *RuntimeList) Delete(runtimeID common.Namespace) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.runtimes, runtimeID)
}

// Empty returns true if and only if the list contains no elements.
func (l *RuntimeList) Empty() bool {
	if l == nil {
		return true
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	return len(l.runtimes) == 0
}

// AccessList is a thread-safe data structure for managing access permissions.
type AccessList struct {
	mu sync.RWMutex

	accessList          map[core.PeerID]*RuntimeList       // Guarded by mutex.
	accessListByRuntime map[common.Namespace][]core.PeerID // Guarded by mutex.

	logger *logging.Logger
}

// NewAccessList constructs an empty access list.
func NewAccessList() *AccessList {
	logger := logging.GetLogger("worker/keymanager/acl")

	return &AccessList{
		accessList:          make(map[core.PeerID]*RuntimeList),
		accessListByRuntime: make(map[common.Namespace][]core.PeerID),
		logger:              logger,
	}
}

// Runtimes returns the IDs of runtimes in which the given peer participates.
func (l *AccessList) Runtimes(peer core.PeerID) *RuntimeList {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.accessList[peer]
}

// Update clears the access list for the specified runtime and adds the provided peers.
func (l *AccessList) Update(runtimeID common.Namespace, peers []core.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Clear any old nodes from the access list.
	for _, peerID := range l.accessListByRuntime[runtimeID] {
		rts := l.accessList[peerID]
		rts.Delete(runtimeID)
		if rts.Empty() {
			delete(l.accessList, peerID)
		}
	}

	// Update the access list.
	for _, peer := range peers {
		rts, ok := l.accessList[peer]
		if !ok {
			rts = NewRuntimeList()
			l.accessList[peer] = rts
		}

		rts.Add(runtimeID)
	}

	// To prevent race conditions when returning runtime access lists, it is essential to always
	// replace the peers array and refrain from making any modifications.
	l.accessListByRuntime[runtimeID] = peers

	l.logger.Debug("new client runtime access policy in effect",
		"runtime_id", runtimeID,
		"peers", peers,
	)
}

// UpdateNodes converts node public keys to peer IDs and updates the access list
// for the specified runtime.
func (l *AccessList) UpdateNodes(runtimeID common.Namespace, nodes []*node.Node) {
	var peers []core.PeerID
	for _, node := range nodes {
		peer, err := p2p.PublicKeyToPeerID(node.P2P.ID)
		if err != nil {
			l.logger.Warn("invalid node P2P ID",
				"err", err,
				"node_id", node.ID,
			)
			continue
		}
		peers = append(peers, peer)
	}

	l.Update(runtimeID, peers)
}

// RuntimeAccessLists returns a per-runtime list of allowed peers.
func (l *AccessList) RuntimeAccessLists() []api.RuntimeAccessList {
	l.mu.RLock()
	defer l.mu.RUnlock()

	rals := make([]api.RuntimeAccessList, 0, len(l.accessListByRuntime))
	for rt, ps := range l.accessListByRuntime {
		ral := api.RuntimeAccessList{
			RuntimeID: rt,
			Peers:     ps,
		}
		rals = append(rals, ral)
	}

	return rals
}

// PeerMap is a thread-safe data structure for translating peer IDs to node IDs.
type PeerMap struct {
	mu    sync.RWMutex
	peers map[core.PeerID]signature.PublicKey // Guarded by mutex.
}

// NewPeerMap creates an empty peer map.
func NewPeerMap() *PeerMap {
	return &PeerMap{}
}

// Update updates the map with the provided peers.
func (m *PeerMap) Update(peers map[core.PeerID]signature.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.peers = peers
}

// NodeID returns the node ID of the specified peer.
func (m *PeerMap) NodeID(peer core.PeerID) (signature.PublicKey, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	node, ok := m.peers[peer]
	return node, ok
}
