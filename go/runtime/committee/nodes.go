package committee

import (
	"context"
	"fmt"
	"sync"

	"github.com/eapache/channels"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

// NodeUpdate is a node update.
type NodeUpdate struct {
	Update *node.Node
	Reset  bool
	Freeze *FreezeEvent
}

// FreezeEvent is a committee freeze event.
type FreezeEvent struct {
	Version int64
}

// NodeDescriptorLookup is the node descriptor lookup interface.
type NodeDescriptorLookup interface {
	// Lookup looks up a node descriptor given its identifier.
	Lookup(id signature.PublicKey) *node.Node

	// LookupByPeerID looks up a node descriptor given its P2P peer ID.
	LookupByPeerID(id signature.PublicKey) *node.Node

	// WatchNodeUpdates subscribes to notifications about node descriptor updates.
	//
	// On subscription the current nodes will be sent immediately.
	WatchNodeUpdates() (<-chan *NodeUpdate, pubsub.ClosableSubscription, error)
}

// NodeDescriptorWatcher is the node descriptor watcher interface.
type NodeDescriptorWatcher interface {
	NodeDescriptorLookup

	// Reset clears the watcher so it doesn't watch any nodes.
	Reset()

	// Freeze freezes the node descriptor watcher so no new nodes can be watched.
	//
	// In order to watch new nodes, the caller must first call Reset. Calling this method on an
	// already frozen watcher may result in a panic.
	//
	// The version argument may be used to signal which committee version this is.
	Freeze(version int64)

	// WatchNode starts watching a given node.
	//
	// It returns the latest version of the node descriptor.
	WatchNode(ctx context.Context, id signature.PublicKey) (*node.Node, error)
}

type nodeDescriptorWatcher struct {
	sync.RWMutex

	registry registry.Backend

	ctx context.Context

	frozen        bool
	version       int64
	nodes         map[signature.PublicKey]*node.Node
	nodesByPeerID map[signature.PublicKey]*node.Node

	notifier *pubsub.Broker

	logger *logging.Logger
}

func (nw *nodeDescriptorWatcher) Reset() {
	nw.Lock()
	defer nw.Unlock()

	nw.frozen = false
	nw.nodes = make(map[signature.PublicKey]*node.Node)
	nw.nodesByPeerID = make(map[signature.PublicKey]*node.Node)

	nw.notifier.Broadcast(&NodeUpdate{
		Reset: true,
	})
}

func (nw *nodeDescriptorWatcher) Freeze(version int64) {
	nw.Lock()
	defer nw.Unlock()

	if nw.frozen {
		panic("committee: Freeze called on a frozen node descriptor watcher")
	}
	nw.frozen = true
	nw.version = version

	nw.notifier.Broadcast(&NodeUpdate{
		Freeze: &FreezeEvent{Version: version},
	})
}

func (nw *nodeDescriptorWatcher) WatchNode(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	nw.Lock()
	defer nw.Unlock()

	if nw.frozen {
		// If the watcher is frozen it should first be reset.
		return nil, fmt.Errorf("committee: node descriptor watcher is frozen")
	}

	if n, ok := nw.nodes[id]; ok {
		// Already watching this node, no need to do anything.
		return n, nil
	}

	// Fetch the latest version of the node from registry.
	n, err := nw.registry.GetNode(ctx, &registry.IDQuery{ID: id, Height: consensus.HeightLatest})
	if err != nil {
		return nil, fmt.Errorf("committee: failed to fetch node info: %w", err)
	}

	nw.updateLocked(n)
	return n, nil
}

func (nw *nodeDescriptorWatcher) Lookup(id signature.PublicKey) *node.Node {
	nw.RLock()
	defer nw.RUnlock()

	if nw.nodes == nil {
		return nil
	}
	return nw.nodes[id]
}

func (nw *nodeDescriptorWatcher) LookupByPeerID(id signature.PublicKey) *node.Node {
	nw.RLock()
	defer nw.RUnlock()

	if nw.nodesByPeerID == nil {
		return nil
	}
	return nw.nodesByPeerID[id]
}

func (nw *nodeDescriptorWatcher) updateLocked(n *node.Node) {
	if nw.nodes == nil || nw.nodesByPeerID == nil {
		return
	}

	if old := nw.nodes[n.ID]; old != nil {
		delete(nw.nodesByPeerID, old.P2P.ID)
	}
	nw.nodes[n.ID] = n
	nw.nodesByPeerID[n.P2P.ID] = n

	nw.notifier.Broadcast(&NodeUpdate{
		Update: n,
	})
}

func (nw *nodeDescriptorWatcher) WatchNodeUpdates() (<-chan *NodeUpdate, pubsub.ClosableSubscription, error) {
	sub := nw.notifier.Subscribe()
	ch := make(chan *NodeUpdate)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (nw *nodeDescriptorWatcher) worker(ch <-chan *registry.NodeEvent, sub pubsub.ClosableSubscription) {
	defer sub.Close()

	for {
		select {
		case <-nw.ctx.Done():
			return
		case ev := <-ch:
			func() {
				nw.Lock()
				defer nw.Unlock()

				if _, ok := nw.nodes[ev.Node.ID]; !ok {
					// Ignore nodes that we are not explicitly watching.
					return
				}

				nw.logger.Debug("updating node descriptor",
					"node", ev.Node.ID,
				)

				nw.updateLocked(ev.Node)
			}()
		}
	}
}

// NewNodeDescriptorWatcher creates a new node descriptor watcher.
func NewNodeDescriptorWatcher(ctx context.Context, registry registry.Backend) (NodeDescriptorWatcher, error) {
	// Subscribe to node updates.
	ch, sub, err := registry.WatchNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("committee: failed to watch nodes: %w", err)
	}

	nw := &nodeDescriptorWatcher{
		registry: registry,
		ctx:      ctx,
		logger:   logging.GetLogger("runtime/committee/nodedescriptorwatcher"),
	}
	nw.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		nw.RLock()
		defer nw.RUnlock()

		ch.In() <- &NodeUpdate{Reset: true}
		for _, n := range nw.nodes {
			ch.In() <- &NodeUpdate{Update: n}
		}
		if nw.frozen {
			ch.In() <- &NodeUpdate{Freeze: &FreezeEvent{Version: nw.version}}
		}
	})
	nw.Reset()

	go nw.worker(ch, sub)

	return nw, nil
}
