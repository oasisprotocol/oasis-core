package nodes

import (
	"context"
	"fmt"
	"sync"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const roleTagPrefix = "role"

func tagForRole(r node.RolesMask) string {
	return fmt.Sprintf("%s-%s", roleTagPrefix, r.String())
}

// TagsForRoleMask returns node lookup tags for node roles.
func TagsForRoleMask(nodeRoles node.RolesMask) (tags []string) {
	for _, r := range node.Roles() {
		if nodeRoles&r != 0 {
			tags = append(tags, tagForRole(r))
		}
	}
	return
}

type runtimeNodesWatcher struct { // nolint: maligned
	sync.RWMutex

	registry registry.Backend

	runtimeID common.Namespace

	nodes         map[signature.PublicKey]*node.Node
	nodesByPeerID map[signature.PublicKey]*node.Node
	tags          map[signature.PublicKey][]string

	notifier *pubsub.Broker

	logger *logging.Logger
}

// Implements NodeDescriptorLookup.
func (rw *runtimeNodesWatcher) Lookup(id signature.PublicKey) *node.Node {
	rw.RLock()
	defer rw.RUnlock()

	return rw.nodes[id]
}

// Implements NodeDescriptorLookup.
func (rw *runtimeNodesWatcher) LookupByPeerID(id signature.PublicKey) *node.Node {
	rw.RLock()
	defer rw.RUnlock()

	return rw.nodesByPeerID[id]
}

// Implements NodeDescriptorLookup.
func (rw *runtimeNodesWatcher) LookupTags(id signature.PublicKey) []string {
	rw.RLock()
	defer rw.RUnlock()

	return rw.tags[id]
}

// Implements NodeDescriptorLookup.
func (rw *runtimeNodesWatcher) GetNodes() []*node.Node {
	rw.RLock()
	defer rw.RUnlock()

	nodes := make([]*node.Node, 0, len(rw.nodes))
	for _, n := range rw.nodes {
		nodes = append(nodes, n)
	}

	return nodes
}

// Implements NodeDescriptorLookup.
func (rw *runtimeNodesWatcher) WatchNodeUpdates() (<-chan *NodeUpdate, pubsub.ClosableSubscription, error) {
	sub := rw.notifier.Subscribe()
	ch := make(chan *NodeUpdate)
	sub.Unwrap(ch)

	return ch, sub, nil
}

// Implements NodeDescriptorLookup.
func (rw *runtimeNodesWatcher) Versioned() bool {
	// This is a non-versioned watcher, it will watch nodes as it gets them.
	return false
}

func (rw *runtimeNodesWatcher) updateLocked(n *node.Node) {
	if old := rw.nodes[n.ID]; old != nil {
		delete(rw.nodesByPeerID, old.P2P.ID)
	}
	rw.nodes[n.ID] = n
	rw.nodesByPeerID[n.P2P.ID] = n
	rw.tags[n.ID] = TagsForRoleMask(n.Roles)

	rw.notifier.Broadcast(&NodeUpdate{
		Update: n,
	})
}

func (rw *runtimeNodesWatcher) removeLocked(n *node.Node) {
	old := rw.nodes[n.ID]
	if old == nil {
		return
	}

	delete(rw.nodesByPeerID, old.P2P.ID)
	delete(rw.nodes, n.ID)
	delete(rw.tags, n.ID)

	rw.notifier.Broadcast(&NodeUpdate{
		Delete: &n.ID,
	})
}

func (rw *runtimeNodesWatcher) watchRuntimeNodeUpdates(ctx context.Context, ch <-chan *registry.NodeEvent, sub pubsub.ClosableSubscription) {
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:

			if ev.Node.GetRuntime(rw.runtimeID) == nil {
				continue
			}

			rw.Lock()
			switch ev.IsRegistration {
			case false:
				rw.removeLocked(ev.Node)
			case true:
				rw.updateLocked(ev.Node)
			}
			rw.Unlock()
		}
	}
}

// NewRuntimeNodeLookup creates a new runtime node lookup.
//
// Runtime node lookup watches all registered nodes for the provided runtime.
// Aditionally, watched nodes are tagged by node roles.
func NewRuntimeNodeLookup(
	ctx context.Context,
	registry registry.Backend,
	runtimeID common.Namespace,
) (NodeDescriptorLookup, error) {
	rw := &runtimeNodesWatcher{
		registry:      registry,
		runtimeID:     runtimeID,
		nodes:         make(map[signature.PublicKey]*node.Node),
		nodesByPeerID: make(map[signature.PublicKey]*node.Node),
		tags:          make(map[signature.PublicKey][]string),
		logger: logging.GetLogger("runtime/nodes/watcher").With(
			"runtime_id", runtimeID,
		),
	}

	rw.notifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		rw.RLock()
		defer rw.RUnlock()

		ch.In() <- &NodeUpdate{Reset: true}
		for _, n := range rw.nodes {
			ch.In() <- &NodeUpdate{Update: n}
		}
	})

	ch, sub, err := registry.WatchNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("runtime: failed to watch nodes: %w", err)
	}

	go rw.watchRuntimeNodeUpdates(ctx, ch, sub)

	return rw, nil
}
