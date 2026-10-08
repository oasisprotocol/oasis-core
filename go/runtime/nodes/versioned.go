package nodes

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// VersionedNodeDescriptorWatcher is the versioned node descriptor watcher.
type VersionedNodeDescriptorWatcher struct {
	sync.RWMutex

	consensus consensus.Service

	frozen        bool
	version       int64
	nodes         map[signature.PublicKey]*node.Node
	nodesByPeerID map[signature.PublicKey]*node.Node
	tags          map[signature.PublicKey][]string

	notifier *pubsub.Broker

	logger *logging.Logger
}

// NewVersionedNodeDescriptorWatcher creates a new base versioned node descriptor watcher.
//
// This watcher will only track nodes that will be explicitly marked to watch
// via WatchNode/WatchNodeWithTags methods.
func NewVersionedNodeDescriptorWatcher(consensus consensus.Service) *VersionedNodeDescriptorWatcher {
	nw := &VersionedNodeDescriptorWatcher{
		consensus: consensus,
		logger:    logging.GetLogger("runtime/committee/nodedescriptorwatcher"),
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

	return nw
}

// Serve starts the watcher.
func (nw *VersionedNodeDescriptorWatcher) Serve(ctx context.Context) error {
	return nw.watchRuntimeNodeUpdates(ctx)
}

// Reset clears the watcher so it doesn't watch any nodes.
func (nw *VersionedNodeDescriptorWatcher) Reset() {
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

// BumpVersion updates the committee version without performing a reset.
//
// This method may be used when the new committee version is exactly the same as the old one
// without introducing a needless reset.
//
// The watcher must have previously been frozen. Calling this method on an unfrozen watcher may
// result in a panic.
func (nw *VersionedNodeDescriptorWatcher) BumpVersion(version int64) {
	nw.Lock()
	defer nw.Unlock()

	if !nw.frozen {
		panic("committee: BumpVersion called on an unfrozen node descriptor watcher")
	}
	nw.version = version

	nw.notifier.Broadcast(&NodeUpdate{
		BumpVersion: &VersionEvent{Version: version},
	})
}

// Freeze freezes the node descriptor watcher so no new nodes can be watched.
//
// In order to watch new nodes, the caller must first call Reset. Calling this method on an
// already frozen watcher may result in a panic.
//
// The version argument may be used to signal which committee version this is.
func (nw *VersionedNodeDescriptorWatcher) Freeze(version int64) {
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

// WatchNode starts watching a given node.
//
// It returns the latest version of the node descriptor.
func (nw *VersionedNodeDescriptorWatcher) WatchNode(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	return nw.WatchNodeWithTag(ctx, id, "")
}

// WatchNodeWithTag starts watching a given node, tagging it with a specific tag.
//
// It returns the latest version of the node descriptor.
func (nw *VersionedNodeDescriptorWatcher) WatchNodeWithTag(ctx context.Context, id signature.PublicKey, tag string) (*node.Node, error) {
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
	n, err := nw.consensus.Registry().GetNode(ctx, &registry.IDQuery{ID: id, Height: consensus.HeightLatest})
	if err != nil {
		return nil, fmt.Errorf("committee: failed to fetch node info: %w", err)
	}

	nw.updateLocked(n, tag)
	return n, nil
}

func (nw *VersionedNodeDescriptorWatcher) Lookup(id signature.PublicKey) *node.Node {
	nw.RLock()
	defer nw.RUnlock()

	if nw.nodes == nil {
		return nil
	}
	return nw.nodes[id]
}

func (nw *VersionedNodeDescriptorWatcher) LookupByPeerID(id signature.PublicKey) *node.Node {
	nw.RLock()
	defer nw.RUnlock()

	if nw.nodesByPeerID == nil {
		return nil
	}
	return nw.nodesByPeerID[id]
}

func (nw *VersionedNodeDescriptorWatcher) GetNodes() []*node.Node {
	nw.RLock()
	defer nw.RUnlock()

	nodes := make([]*node.Node, 0, len(nw.nodes))
	for _, v := range nw.nodes {
		nodes = append(nodes, v)
	}
	return nodes
}

func (nw *VersionedNodeDescriptorWatcher) LookupTags(id signature.PublicKey) []string {
	nw.RLock()
	defer nw.RUnlock()

	if nw.tags == nil {
		return nil
	}
	return nw.tags[id]
}

func (nw *VersionedNodeDescriptorWatcher) updateLocked(n *node.Node, tag string) {
	if nw.nodes == nil || nw.nodesByPeerID == nil {
		return
	}

	if old := nw.nodes[n.ID]; old != nil {
		delete(nw.nodesByPeerID, old.P2P.ID)
	}
	nw.nodes[n.ID] = n
	nw.nodesByPeerID[n.P2P.ID] = n

	if len(tag) > 0 {
		if !slices.Contains(nw.tags[n.ID], tag) {
			nw.tags[n.ID] = append(nw.tags[n.ID], tag)
		}
	}

	nw.notifier.Broadcast(&NodeUpdate{
		Update: n,
	})
}

func (nw *VersionedNodeDescriptorWatcher) WatchNodeUpdates() (<-chan *NodeUpdate, pubsub.ClosableSubscription, error) {
	sub := nw.notifier.Subscribe()
	ch := make(chan *NodeUpdate)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (nw *VersionedNodeDescriptorWatcher) watchRuntimeNodeUpdates(ctx context.Context) error {
	nw.logger.Debug("waiting consensus sync")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-nw.consensus.Synced():
	}
	nw.logger.Debug("consensus synced")

	// Subscribe to node updates.
	ch, sub, err := nw.consensus.Registry().WatchNodes(ctx)
	if err != nil {
		nw.logger.Error(
			"failed to watch nodes",
			"err", err,
		)
		return fmt.Errorf("failed to watch nodes: %w", err)
	}
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-ch:
			func() {
				nw.Lock()
				defer nw.Unlock()

				if _, ok := nw.nodes[ev.Node.ID]; !ok {
					// Ignore nodes that we are not explicitly watching.
					return
				}

				nw.logger.Debug(
					"updating node descriptor",
					"node", ev.Node.ID,
				)

				nw.updateLocked(ev.Node, "")
			}()
		}
	}
}

func (nw *VersionedNodeDescriptorWatcher) Versioned() bool {
	// This watcher supports versions.
	return true
}
