// Package nodes provides lookup and watcher utilities for groups of nodes.
package nodes

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

// NodeUpdate is a node update.
type NodeUpdate struct {
	Update *node.Node
	Delete *signature.PublicKey
	Reset  bool

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
	// For non-Versioned descriptor lookups there should be NO Versioned events.
	// On subscription the current nodes will be sent immediately.
	WatchNodeUpdates() (<-chan *NodeUpdate, pubsub.ClosableSubscription, error)

	// Versioned returns true if this descriptor lookup is versioned.
	//
	// Versioned descriptor lookups are suitable to track versioned groups of nodes
	// (e.g. committees versioned by the group number), while non-versioned lookups
	// are suitable for watching non-versioned groups of nodes (e.g. all nodes,
	// or all nodes registered for a specific runtime).
	Versioned() bool
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

		// XXX: This is needed so that we can correctly handle update & delete events.
		prevNodes := make(map[signature.PublicKey]*node.Node)
		prevTags := make(map[signature.PublicKey][]string)

		for {
			nu, ok := <-ch
			if !ok {
				return
			}

			switch {
			case nu.Reset:
				prevNodes = make(map[signature.PublicKey]*node.Node)
				prevTags = make(map[signature.PublicKey][]string)
			case nu.Update != nil:
				oldNode, nodeExists := prevNodes[nu.Update.ID]
				oldTags, exists := prevTags[nu.Update.ID]
				tags := f.base.LookupTags(nu.Update.ID)

				matchesBeforeUpdate := nodeExists && exists && f.filter(oldNode, oldTags)
				matchesAfterUpdate := f.filter(nu.Update, tags)

				switch matchesAfterUpdate {
				case true:
					// If node matches filters, locally save the node and tags.
					prevNodes[nu.Update.ID] = nu.Update
					prevTags[nu.Update.ID] = tags
				case false:
					// If node doesn't match filters anymore, it can be deleted from local maps.
					delete(prevNodes, nu.Update.ID)
					delete(prevTags, nu.Update.ID)
				}

				switch {
				case matchesBeforeUpdate && !matchesAfterUpdate:
					// Node passed filters before update, now doesn't.
					// Send a delete event.
					filteredCh <- &NodeUpdate{Delete: &nu.Update.ID}

					continue
				case !matchesBeforeUpdate && !matchesAfterUpdate:
					// Node didn't pass filters before update, still doesn't.
					// Don't send any events.
					continue
				default:
					// Otherwise propagate the event.
				}
			case nu.Delete != nil:
				oldNode, existsNode := prevNodes[*nu.Delete]
				oldTags, exists := prevTags[*nu.Delete]
				matchesBeforeDelete := existsNode && exists && f.filter(oldNode, oldTags)

				// Delete stored values for the node.
				delete(prevNodes, *nu.Delete)
				delete(prevTags, *nu.Delete)

				if !matchesBeforeDelete {
					// If node didn't match filters before, don't propage the
					// delete event.
					continue
				}
			}

			filteredCh <- nu
		}
	}()

	return filteredCh, sub, nil
}

func (f *filteredNodeDescriptorLookup) Versioned() bool {
	return f.base.Versioned()
}

// NewFilteredNodeLookup creates a NodeDescriptorLookup with a node filter function applied.
func NewFilteredNodeLookup(nl NodeDescriptorLookup, f NodeFilterFunc) NodeDescriptorLookup {
	return &filteredNodeDescriptorLookup{
		filter: f,
		base:   nl,
	}
}

// IgnoreNodeFilter returns a node filter function that filters out the node with
// the provided id.
func IgnoreNodeFilter(id signature.PublicKey) NodeFilterFunc {
	return func(node *node.Node, _ []string) bool {
		return !node.ID.Equal(id)
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

// WithAllFilters combines multiple filters into a single NodeFilterFunc that
// only includes nodes passing all of the provided filters.
func WithAllFilters(filters ...NodeFilterFunc) NodeFilterFunc {
	return func(n *node.Node, tags []string) bool {
		for _, f := range filters {
			if !f(n, tags) {
				return false
			}
		}
		return true
	}
}
