package committee

import (
	"context"
	"fmt"
	"sync"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// NodeUpdate is a node update.
type NodeUpdate struct {
	Update      *node.Node
	Reset       bool
	Freeze      *VersionEvent
	BumpVersion *VersionEvent
}

// VersionEvent is a committee version event.
type VersionEvent struct {
	Version int64
}

// NodeDescriptorLookup is the node descriptor lookup interface.
type NodeDescriptorLookup interface {
	// Lookup looks up a node descriptor given its identifier.
	Lookup(id signature.PublicKey) *node.Node

	// LookupByPeerID looks up a node descriptor given its P2P peer ID.
	LookupByPeerID(id signature.PublicKey) *node.Node

	// LookupTags looks up tags for a given node.
	LookupTags(id signature.PublicKey) []string

	// GetNodes returns current list of nodes.
	GetNodes() []*node.Node

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

	// BumpVersion updates the committee version without performing a reset.
	//
	// This method may be used when the new committee version is exactly the same as the old one
	// without introducing a needless reset.
	//
	// The watcher must have previously been frozen. Calling this method on an unfrozen watcher may
	// result in a panic.
	BumpVersion(version int64)

	// WatchNode starts watching a given node.
	//
	// It returns the latest version of the node descriptor.
	WatchNode(ctx context.Context, id signature.PublicKey) (*node.Node, error)

	// WatchNodeWithTag starts watching a given node, tagging it with a specific tag.
	//
	// It returns the latest version of the node descriptor.
	WatchNodeWithTag(ctx context.Context, id signature.PublicKey, tag string) (*node.Node, error)
}

type nodeDescriptorWatcher struct {
	sync.RWMutex

	registry registry.Backend

	ctx context.Context

	frozen        bool
	version       int64
	nodes         map[signature.PublicKey]*node.Node
	nodesByPeerID map[signature.PublicKey]*node.Node
	tags          map[signature.PublicKey][]string

	notifier *pubsub.Broker

	logger *logging.Logger
}

func (nw *nodeDescriptorWatcher) Reset() {
	nw.Lock()
	defer nw.Unlock()

	nw.frozen = false
	nw.nodes = make(map[signature.PublicKey]*node.Node)
	nw.nodesByPeerID = make(map[signature.PublicKey]*node.Node)
	nw.tags = make(map[signature.PublicKey][]string)

	nw.notifier.Broadcast(&NodeUpdate{
		Reset: true,
	})
}

func (nw *nodeDescriptorWatcher) BumpVersion(version int64) {
	nw.Lock()
	defer nw.Unlock()

	if !nw.frozen {
		panic("committee: BumpVersion called on an unfrozed node descriptor watcher")
	}
	nw.version = version

	nw.notifier.Broadcast(&NodeUpdate{
		BumpVersion: &VersionEvent{Version: version},
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
		Freeze: &VersionEvent{Version: version},
	})
}

func (nw *nodeDescriptorWatcher) WatchNode(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	return nw.WatchNodeWithTag(ctx, id, "")
}

func (nw *nodeDescriptorWatcher) WatchNodeWithTag(ctx context.Context, id signature.PublicKey, tag string) (*node.Node, error) {
	nw.Lock()
	defer nw.Unlock()

	if nw.frozen {
		// If the watcher is frozen it should first be reset.
		return nil, fmt.Errorf("committee: node descriptor watcher is frozen")
	}

	if n, ok := nw.nodes[id]; ok {
		// Already watching this node, we may only need to update its tag.
		if len(tag) > 0 {
			nw.updateLocked(n, tag)
		}
		return n, nil
	}

	// Fetch the latest version of the node from registry.
	n, err := nw.registry.GetNode(ctx, &registry.IDQuery{ID: id, Height: consensus.HeightLatest})
	if err != nil {
		return nil, fmt.Errorf("committee: failed to fetch node info: %w", err)
	}

	nw.updateLocked(n, tag)
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

func (nw *nodeDescriptorWatcher) GetNodes() []*node.Node {
	nw.RLock()
	defer nw.RUnlock()

	nodes := make([]*node.Node, 0, len(nw.nodes))
	for _, v := range nw.nodes {
		nodes = append(nodes, v)
	}
	return nodes
}

func (nw *nodeDescriptorWatcher) LookupTags(id signature.PublicKey) []string {
	nw.RLock()
	defer nw.RUnlock()

	if nw.tags == nil {
		return nil
	}
	return nw.tags[id]
}

func (nw *nodeDescriptorWatcher) updateLocked(n *node.Node, tag string) {
	if nw.nodes == nil || nw.nodesByPeerID == nil {
		return
	}

	if old := nw.nodes[n.ID]; old != nil {
		delete(nw.nodesByPeerID, old.P2P.ID)
	}
	nw.nodes[n.ID] = n
	nw.nodesByPeerID[n.P2P.ID] = n

	if len(tag) > 0 {
		var hasTag bool
		for _, t := range nw.tags[n.ID] {
			if t == tag {
				hasTag = true
				break
			}
		}
		if !hasTag {
			nw.tags[n.ID] = append(nw.tags[n.ID], tag)
		}
	}

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

				nw.updateLocked(ev.Node, "")
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
	nw.notifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		nw.RLock()
		defer nw.RUnlock()

		ch.In() <- &NodeUpdate{Reset: true}
		for _, n := range nw.nodes {
			ch.In() <- &NodeUpdate{Update: n}
		}
		if nw.frozen {
			ch.In() <- &NodeUpdate{Freeze: &VersionEvent{Version: nw.version}}
		}
	})
	nw.Reset()

	go nw.worker(ch, sub)

	return nw, nil
}

// NodeFilterFunc is a function that performs node filtering.
type NodeFilterFunc func(*node.Node, []string) bool

type filteredNodeDescriptorLookup struct {
	filter NodeFilterFunc
	base   NodeDescriptorLookup
}

// Implements NodeDescriptorLookup.
func (f *filteredNodeDescriptorLookup) Lookup(id signature.PublicKey) *node.Node {
	tags := f.base.LookupTags(id)
	n := f.base.Lookup(id)
	if !f.filter(n, tags) {
		return nil
	}
	return n
}

// Implements NodeDescriptorLookup.
func (f *filteredNodeDescriptorLookup) LookupByPeerID(id signature.PublicKey) *node.Node {
	tags := f.base.LookupTags(id)
	n := f.base.LookupByPeerID(id)
	if !f.filter(n, tags) {
		return nil
	}
	return n
}

// Implements NodeDescriptorLookup.
func (f *filteredNodeDescriptorLookup) LookupTags(id signature.PublicKey) []string {
	return f.base.LookupTags(id)
}

// Implements NodeDescriptorLookup.
func (f *filteredNodeDescriptorLookup) GetNodes() (filtered []*node.Node) {
	for _, v := range f.base.GetNodes() {
		tags := f.base.LookupTags(v.ID)
		if f.filter(v, tags) {
			filtered = append(filtered, v)
		}
	}
	return
}

// Implements NodeDescriptorLookup.
func (f *filteredNodeDescriptorLookup) WatchNodeUpdates() (<-chan *NodeUpdate, pubsub.ClosableSubscription, error) {
	filteredCh := make(chan *NodeUpdate)
	ch, sub, err := f.base.WatchNodeUpdates()
	if err != nil {
		return nil, nil, err
	}

	go func() {
		defer close(filteredCh)

		for {
			nu, ok := <-ch
			if !ok {
				return
			}
			if nu.Update != nil {
				tags := f.base.LookupTags(nu.Update.ID)
				if !f.filter(nu.Update, tags) {
					continue
				}
			}
			filteredCh <- nu
		}
	}()

	return filteredCh, sub, nil
}

// NewFilteredNodeLookup creates a NodeDescriptorLookup with a node filter function applied.
func NewFilteredNodeLookup(nl NodeDescriptorLookup, f NodeFilterFunc) NodeDescriptorLookup {
	return &filteredNodeDescriptorLookup{
		filter: f,
		base:   nl,
	}
}

// TagFilter returns a node filter function that only includes nodes with the given tag.
func TagFilter(tag string) NodeFilterFunc {
	return func(_ *node.Node, tags []string) bool {
		for _, t := range tags {
			if t == tag {
				return true
			}
		}
		return false
	}
}
