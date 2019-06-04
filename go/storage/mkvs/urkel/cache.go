package urkel

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

// cache handles the in-memory tree cache.
type cache struct {
	db db.NodeDB
	rs syncer.ReadSyncer

	// pendingRoot is the pending root which will become the new root if
	// the currently cached contents is committed.
	pendingRoot *internal.Pointer
	// syncRoot is the root at which all node database and syncer cache
	// lookups will be done.
	syncRoot hash.Hash

	// Current size of leaf values.
	valueSize uint64
	// Current number of internal nodes.
	internalNodeCount uint64
	// Current number leaf nodes.
	leafNodeCount uint64

	// Maximum capacity of internal and leaf nodes.
	nodeCapacity uint64
	// Maximum capacity of leaf values.
	valueCapacity uint64
	// Prefetch depth.
	prefetchDepth internal.DepthType
	// Syncer remote GetNode timeout.
	syncerGetNodeTimeout time.Duration
	// Syncer remote subtree prefetch timeout.
	syncerPrefetchTimeout time.Duration

	lruNodes  *list.List
	lruValues *list.List
}

// MaxPrefetchDepth is the maximum depth of the prefeteched tree
const MaxPrefetchDepth = 255

func newCache(ndb db.NodeDB, rs syncer.ReadSyncer) cache {
	return cache{
		db:                    ndb,
		rs:                    rs,
		lruNodes:              list.New(),
		lruValues:             list.New(),
		syncerGetNodeTimeout:  1 * time.Second,
		syncerPrefetchTimeout: 5 * time.Second,
	}
}

func (c *cache) setSyncRoot(root hash.Hash) {
	c.syncRoot = root
}

func (c *cache) setPendingRoot(ptr *internal.Pointer) {
	c.pendingRoot = ptr
}

func (c *cache) newLeafNodePtr(node *internal.LeafNode) *internal.Pointer {
	return &internal.Pointer{
		Node: node,
	}
}

func (c *cache) newLeafNode(key []byte, val []byte) *internal.Pointer {
	return c.newLeafNodePtr(&internal.LeafNode{
		Key:   key[:],
		Value: c.newValue(val),
	})
}

func (c *cache) newInternalNodePtr(node *internal.InternalNode) *internal.Pointer {
	return &internal.Pointer{
		Node: node,
	}
}

func (c *cache) newInternalNode(leafNode *internal.Pointer, left *internal.Pointer, right *internal.Pointer) *internal.Pointer {
	return c.newInternalNodePtr(&internal.InternalNode{
		LeafNode: leafNode,
		Left:     left,
		Right:    right,
	})
}

// useNode moves the node to the front of the LRU list.
func (c *cache) useNode(ptr *internal.Pointer) {
	if ptr.LRU == nil {
		return
	}
	c.lruNodes.MoveToFront(ptr.LRU)
}

// useValue moves the value to the front of the LRU list.
func (c *cache) useValue(v *internal.Value) {
	if v.LRU == nil {
		return
	}
	c.lruValues.MoveToFront(v.LRU)
}

// commitNode makes the node eligible for eviction.
func (c *cache) commitNode(ptr *internal.Pointer) {
	if !ptr.IsClean() {
		panic("urkel: commitNode called on dirty node")
	}
	if ptr == nil || ptr.Node == nil {
		return
	}
	if ptr.LRU != nil {
		c.useNode(ptr)
		return
	}

	// Evict nodes till there is enough capacity.
	if c.nodeCapacity > 0 && c.nodeCapacity-(c.internalNodeCount+c.leafNodeCount) < 1 {
		c.evictNodes(1)
	}

	ptr.LRU = c.lruNodes.PushFront(ptr)
	switch ptr.Node.(type) {
	case *internal.InternalNode:
		c.internalNodeCount++
	case *internal.LeafNode:
		c.leafNodeCount++
	}
}

// commitValue makes the value eligible for eviction.
func (c *cache) commitValue(v *internal.Value) {
	if !v.Clean {
		panic("urkel: commitValue called on dirty value")
	}
	if v.LRU != nil {
		c.useValue(v)
		return
	}
	if v.Value == nil {
		return
	}

	valueSize := uint64(len(v.Value))

	// Evict values till there is enough capacity.
	if c.valueCapacity > 0 && valueSize > c.valueCapacity-c.valueSize {
		c.evictValues(valueSize)
	}

	v.LRU = c.lruValues.PushFront(v)
	c.valueSize += valueSize
}

func (c *cache) newValuePtr(v *internal.Value) *internal.Value {
	// TODO: Deduplicate values.
	return v
}

func (c *cache) newValue(val []byte) *internal.Value {
	return c.newValuePtr(&internal.Value{Value: val})
}

// tryRemoveNode tries to removes a tree node.
//
// Note that the node may not be actually removed if it is not possible
// to do so (e.g., an internal node which still has children).
func (c *cache) tryRemoveNode(ptr *internal.Pointer) {
	if ptr.LRU == nil {
		// Node has not yet been committed to cache.
		return
	}

	switch n := ptr.Node.(type) {
	case *internal.InternalNode:
		// We can only remove internal nodes if they have no cached children or
		// leaf nodes as otherwise we would need to remove the whole subtree.
		if (n.LeafNode != nil && n.LeafNode.Node != nil) || (n.Left != nil && n.Left.Node != nil) || (n.Right != nil && n.Right.Node != nil) {
			return
		}
	}

	c.lruNodes.Remove(ptr.LRU)

	switch n := ptr.Node.(type) {
	case *internal.InternalNode:
		c.internalNodeCount--
	case *internal.LeafNode:
		// Also remove the value
		c.removeValue(n.Value)
		c.leafNodeCount--
	}

	ptr.Node = nil
	ptr.LRU = nil
}

// removeValue removes a value.
func (c *cache) removeValue(v *internal.Value) {
	if v.LRU == nil {
		// Value has not yet been committed to cache.
		return
	}

	c.lruValues.Remove(v.LRU)
	c.valueSize -= uint64(len(v.Value))
	v.Value = nil
	v.LRU = nil
}

// evictValues tries to evict values from the cache.
func (c *cache) evictValues(targetCapacity uint64) {
	for c.lruValues.Len() > 0 && c.valueCapacity-c.valueSize < targetCapacity {
		elem := c.lruValues.Back()
		v := elem.Value.(*internal.Value)
		c.removeValue(v)
	}
}

// evictNodes tries to evict nodes from the cache.
func (c *cache) evictNodes(targetCapacity uint64) {
	// TODO: Consider optimizing this to know which nodes are eligible for removal.
	for c.lruNodes.Len() > 0 && c.nodeCapacity-(c.internalNodeCount+c.leafNodeCount) < targetCapacity {
		elem := c.lruNodes.Back()
		n := elem.Value.(*internal.Pointer)
		c.tryRemoveNode(n)
	}
}

func (c *cache) derefNodeID(ctx context.Context, id internal.NodeID) (*internal.Pointer, error) {
	curPtr := c.pendingRoot
	var d internal.DepthType
	for d = 0; d < id.Depth; d++ {
		node, err := c.derefNodePtr(ctx, id.AtDepth(d), curPtr, nil)
		if err != nil {
			return nil, err
		}

		switch n := node.(type) {
		case nil:
			return nil, nil
		case *internal.InternalNode:
			if id.Path.GetBit(d) {
				curPtr = n.Right
			} else {
				curPtr = n.Left
			}
		case *internal.LeafNode:
			break
		}
	}

	return curPtr, nil
}

// derefNodePtr dereferences an internal node pointer.
//
// This may result in node database accesses or remote syncing if the node
// is not available locally.
func (c *cache) derefNodePtr(ctx context.Context, id internal.NodeID, ptr *internal.Pointer, key internal.Key) (internal.Node, error) {
	if ptr == nil {
		return nil, nil
	}

	if ptr.Node != nil {
		c.useNode(ptr)
		return ptr.Node, nil
	}

	if !ptr.Clean || ptr.Hash.IsEmpty() {
		return nil, nil
	}

	// First, attempt to fetch from the local node database.
	node, err := c.db.GetNode(c.syncRoot, ptr)
	switch err {
	case nil:
		ptr.Node = node
	case db.ErrNodeNotFound:
		// Node not found in local node database, try the syncer.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.syncerGetNodeTimeout)
		defer cancel()

		if key == nil {
			// Target key is not known, we need to prefetch the node.
			if node, err = c.rs.GetNode(ctx, c.syncRoot, id); err != nil {
				return nil, err
			}

			if err = node.Validate(ptr.Hash); err != nil {
				return nil, err
			}

			ptr.Node = node
		} else {
			// If target key is known, we can try prefetching the whole path
			// instead of one node at a time.
			var st *syncer.Subtree
			if st, err = c.rs.GetPath(ctx, c.syncRoot, key, id.Depth); err != nil {
				return nil, err
			}

			var newPtr *internal.Pointer
			if newPtr, err = c.reconstructSubtree(ctx, ptr.Hash, st, id.Depth, id.Depth+MaxPrefetchDepth); err != nil {
				return nil, err
			}

			*ptr = *newPtr
		}
	default:
		return nil, err
	}

	return ptr.Node, nil
}

// derefValue dereferences an internal value pointer.
//
// This may result in node database accesses or remote syncing if the value
// is not available locally.
func (c *cache) derefValue(ctx context.Context, v *internal.Value) ([]byte, error) {
	// Move the accessed value to the front of the LRU list.
	if v.LRU != nil || v.Value != nil {
		c.useValue(v)
		return v.Value, nil
	}

	if !v.Clean {
		return nil, nil
	}

	val, err := c.db.GetValue(v.Hash)
	switch err {
	case nil:
		v.Value = val
	case db.ErrNodeNotFound:
		// Value not found in local node database, try the syncer.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.syncerGetNodeTimeout)
		defer cancel()

		var value []byte
		if value, err = c.rs.GetValue(ctx, c.syncRoot, v.Hash); err != nil {
			return nil, err
		}

		v.Value = value

		if err = v.Validate(v.Hash); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	// Value was fetched, be sure to treat it as committed.
	c.commitValue(v)

	return v.Value, nil
}

// prefetch prefetches a given subtree up to the configured prefetch depth.
func (c *cache) prefetch(ctx context.Context, subtreeRoot hash.Hash, subtreePath internal.Key, depth internal.DepthType) (*internal.Pointer, error) {
	if c.prefetchDepth == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.syncerPrefetchTimeout)
	defer cancel()

	st, err := c.rs.GetSubtree(ctx, c.syncRoot, internal.NodeID{Path: subtreePath, Depth: depth}, c.prefetchDepth)
	switch err {
	case nil:
	case syncer.ErrUnsupported:
		return nil, nil
	default:
		return nil, err
	}

	ptr, err := c.reconstructSubtree(ctx, subtreeRoot, st, 0, c.prefetchDepth)
	if err != nil {
		return nil, err
	}

	return ptr, nil
}

// reconstructSubtree reconstructs a tree summary received through a
// remote syncer.
func (c *cache) reconstructSubtree(ctx context.Context, root hash.Hash, st *syncer.Subtree, depth, maxDepth internal.DepthType) (*internal.Pointer, error) {
	ptr, err := c.doReconstructSummary(st, st.Root, depth, maxDepth)
	if err != nil {
		return nil, err
	}
	if ptr == nil {
		return nil, errors.New("urkel: reconstructed root pointer is nil")
	}

	batch := c.db.NewBatch()
	defer batch.Reset()

	updates := &cacheUpdates{}
	syncRoot, err := doCommit(ctx, c, updates, batch, ptr)
	if err != nil {
		return nil, err
	}
	if !syncRoot.Equal(&root) {
		return nil, fmt.Errorf("urkel: syncer returned bad root (expected: %s got: %s)",
			root,
			syncRoot,
		)
	}

	if err = batch.Commit(root); err != nil {
		return nil, err
	}
	updates.Commit()

	return ptr, nil
}

// doReconstructSummary reconstructs a tree summary received through a
// remote syncer.
func (c *cache) doReconstructSummary(
	st *syncer.Subtree,
	sptr syncer.SubtreePointer,
	depth internal.DepthType,
	maxDepth internal.DepthType,
) (*internal.Pointer, error) {
	if depth > maxDepth {
		return nil, errors.New("urkel: maximum depth exceeded")
	}

	// Mark node as used to ensure that we error if we try to revisit
	// the same node.
	defer st.MarkUsed(sptr)

	if !sptr.Valid {
		return nil, errors.New("urkel: invalid subtree pointer")
	}

	if sptr.Full {
		node, err := st.GetFullNodeAt(sptr.Index)
		if err != nil {
			return nil, err
		}

		var ptr *internal.Pointer
		switch n := node.(type) {
		case *internal.InternalNode:
			// Internal node.
			n.Clean = false
			ptr = c.newInternalNodePtr(n)
		case *internal.LeafNode:
			// Leaf node.
			n.Clean = false
			n.Value = c.newValuePtr(n.Value)
			ptr = c.newLeafNodePtr(n)
		}

		return ptr, nil
	}

	// Summary node.

	s, err := st.GetSummaryAt(sptr.Index)
	if err != nil {
		return nil, err
	}

	// Check if the summary referes to a dead node.
	if s == nil {
		return nil, nil
	}

	leafNode, err := c.doReconstructSummary(st, s.LeafNode, depth, maxDepth)
	if err != nil {
		return nil, err
	}
	left, err := c.doReconstructSummary(st, s.Left, depth+1, maxDepth)
	if err != nil {
		return nil, err
	}
	right, err := c.doReconstructSummary(st, s.Right, depth+1, maxDepth)
	if err != nil {
		return nil, err
	}

	return c.newInternalNode(leafNode, left, right), nil
}
