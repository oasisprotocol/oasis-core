package urkel

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	db "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

// cache handles the in-memory tree cache.
type cache struct {
	sync.Mutex

	db db.NodeDB
	rs syncer.ReadSyncer

	// pendingRoot is the pending root which will become the new root if
	// the currently cached contents is committed.
	pendingRoot *node.Pointer
	// syncRoot is the root at which all node database and syncer cache
	// lookups will be done.
	syncRoot node.Root

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
	prefetchDepth node.Depth
	// Persist all the nodes and values we obtain from the remote syncer?
	persistEverythingFromSyncer bool
	// Syncer remote GetNode timeout.
	syncerGetNodeTimeout time.Duration
	// Syncer remote subtree prefetch timeout.
	syncerPrefetchTimeout time.Duration

	lruNodes  *list.List
	lruValues *list.List
}

// MaxPrefetchDepth is the maximum depth of the prefeteched tree.
const MaxPrefetchDepth = 255

func newCache(ndb db.NodeDB, rs syncer.ReadSyncer) *cache {
	c := &cache{
		db:                          ndb,
		rs:                          rs,
		lruNodes:                    list.New(),
		lruValues:                   list.New(),
		persistEverythingFromSyncer: false,
		syncerGetNodeTimeout:        1 * time.Second,
		syncerPrefetchTimeout:       5 * time.Second,
		valueCapacity:               16 * 1024 * 1024,
		nodeCapacity:                5000,
	}
	// By default the sync root is an empty root.
	c.syncRoot.Empty()

	return c
}

func (c *cache) close() {
	// Clear references.
	c.db = nil
	c.rs = nil
	c.pendingRoot = nil
	c.lruNodes = nil
	c.lruValues = nil

	// Reset sync root.
	c.syncRoot = node.Root{}

	// Reset statistics.
	c.valueSize = 0
	c.internalNodeCount = 0
	c.leafNodeCount = 0
}

func (c *cache) isClosed() bool {
	return c.db == nil
}

func (c *cache) getSyncRoot() node.Root {
	return c.syncRoot
}

func (c *cache) setSyncRoot(root node.Root) {
	c.syncRoot = root
}

func (c *cache) setPendingRoot(ptr *node.Pointer) {
	c.pendingRoot = ptr
}

func (c *cache) newLeafNodePtr(n *node.LeafNode) *node.Pointer {
	return &node.Pointer{
		Node: n,
	}
}

func (c *cache) newLeafNode(key node.Key, val []byte) *node.Pointer {
	return c.newLeafNodePtr(&node.LeafNode{
		Key:   key[:],
		Value: c.newValue(val),
	})
}

func (c *cache) newInternalNodePtr(n *node.InternalNode) *node.Pointer {
	return &node.Pointer{
		Node: n,
	}
}

func (c *cache) newInternalNode(label node.Key, labelBitLength node.Depth, leafNode *node.Pointer, left *node.Pointer, right *node.Pointer) *node.Pointer {
	return c.newInternalNodePtr(&node.InternalNode{
		Label:          label,
		LabelBitLength: labelBitLength,
		LeafNode:       leafNode,
		Left:           left,
		Right:          right,
	})
}

// useNode moves the node to the front of the LRU list.
func (c *cache) useNode(ptr *node.Pointer) {
	if ptr.LRU == nil {
		return
	}
	c.lruNodes.MoveToFront(ptr.LRU)
}

// useValue moves the value to the front of the LRU list.
func (c *cache) useValue(v *node.Value) {
	if v.LRU == nil {
		return
	}
	c.lruValues.MoveToFront(v.LRU)
}

// commitNode makes the node eligible for eviction.
func (c *cache) commitNode(ptr *node.Pointer) {
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
	if c.nodeCapacity > 0 && c.internalNodeCount+c.leafNodeCount+1 > c.nodeCapacity {
		c.evictNodes(1)
	}

	ptr.LRU = c.lruNodes.PushFront(ptr)
	switch n := ptr.Node.(type) {
	case *node.InternalNode:
		c.internalNodeCount++
	case *node.LeafNode:
		c.leafNodeCount++

		if n.Value != nil {
			c.commitValue(n.Value)
		}
	}
}

// commitValue makes the value eligible for eviction.
func (c *cache) commitValue(v *node.Value) {
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
	if c.valueCapacity > 0 && c.valueSize+valueSize > c.valueCapacity {
		c.evictValues(valueSize)
	}

	v.LRU = c.lruValues.PushFront(v)
	c.valueSize += valueSize
}

// rollbackNode marks a tree node as no longer being eligible for
// eviction due to it becoming dirty.
func (c *cache) rollbackNode(ptr *node.Pointer) {
	if ptr.LRU == nil {
		// Node has not yet been committed to cache.
		return
	}

	c.lruNodes.Remove(ptr.LRU)

	switch ptr.Node.(type) {
	case *node.InternalNode:
		c.internalNodeCount--
	case *node.LeafNode:
		c.leafNodeCount--
	}

	ptr.LRU = nil
}

func (c *cache) newValuePtr(v *node.Value) *node.Value {
	// TODO: Deduplicate values.
	return v
}

func (c *cache) newValue(val []byte) *node.Value {
	return c.newValuePtr(&node.Value{Value: val})
}

// removeNode removes a tree node.
func (c *cache) removeNode(ptr *node.Pointer) {
	if ptr.LRU == nil {
		// Node has not yet been committed to cache.
		return
	}

	switch n := ptr.Node.(type) {
	case *node.InternalNode:
		// Remove leaf node and subtrees first.
		if n.LeafNode != nil && n.LeafNode.Node != nil {
			c.removeNode(n.LeafNode)
			n.LeafNode = nil
		}
		if n.Left != nil && n.Left.Node != nil {
			c.removeNode(n.Left)
			n.Left = nil
		}
		if n.Right != nil && n.Right.Node != nil {
			c.removeNode(n.Right)
			n.Right = nil
		}
	}

	c.lruNodes.Remove(ptr.LRU)

	switch n := ptr.Node.(type) {
	case *node.InternalNode:
		c.internalNodeCount--
	case *node.LeafNode:
		// Also remove the value.
		c.removeValue(n.Value)
		c.leafNodeCount--
	}

	ptr.Node = nil
	ptr.LRU = nil
}

// removeValue removes a value.
func (c *cache) removeValue(v *node.Value) {
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
	for c.lruValues.Len() > 0 && c.valueSize+targetCapacity > c.valueCapacity {
		elem := c.lruValues.Back()
		v := elem.Value.(*node.Value)
		c.removeValue(v)
	}
}

// evictNodes tries to evict nodes from the cache.
func (c *cache) evictNodes(targetCapacity uint64) {
	// TODO: Consider optimizing this to know which nodes are eligible for removal.
	for c.lruNodes.Len() > 0 && c.internalNodeCount+c.leafNodeCount+targetCapacity > c.nodeCapacity {
		elem := c.lruNodes.Back()
		n := elem.Value.(*node.Pointer)
		if !n.Clean {
			panic(fmt.Errorf("urkel: tried to evict dirty node %v", n))
		}
		c.removeNode(n)
	}
}

// derefNodeID returns the node spelled out by id.Path of length id.BitDepth.
//
// Beside the node, this function also returns bit depth of the node's parent.
//
// len(id.Path) must always be at least id.BitDepth/8 bytes long.
//
// If there is an InternalNode and its LeafNode spelled out by the same id then
// this function returns an InternalNode. If id is empty, then this function
// returns the root.
//
// WARNING: If the requested node does not exist in the tree, this function
// returns either nil or some other arbitrary node.
func (c *cache) derefNodeID(ctx context.Context, id node.ID) (*node.Pointer, node.Depth, error) {
	curPtr := c.pendingRoot
	bd := node.Depth(0)

	if id.BitDepth == 0 {
		return curPtr, 0, nil
	}

	// There is a border case when id.BitDepth==1. In this case, we check the
	// corresponding root separately.
	if id.BitDepth == 1 && curPtr != nil && curPtr.Node != nil {
		switch n := curPtr.Node.(type) {
		case *node.InternalNode:
			if n.LabelBitLength == 0 {
				if id.Path.GetBit(0) {
					curPtr = n.Right
				} else {
					curPtr = n.Left
				}
				bd = 1
			}
		}
	}

Loop:
	for bd < id.BitDepth-1 {
		// bd is the parent's BitDepth. Add 1 for discriminator bit.
		nd, err := c.derefNodePtr(ctx, node.ID{Path: id.Path, BitDepth: bd + 1}, curPtr, nil)
		if err != nil {
			return nil, 0, err
		}

		switch n := nd.(type) {
		case *node.InternalNode:
			if bd+n.LabelBitLength < id.BitDepth {
				if id.Path.GetBit(bd + n.LabelBitLength) {
					curPtr = n.Right
				} else {
					curPtr = n.Left
				}
				bd += n.LabelBitLength
			} else {
				// end of id.BitDepth reached
				break Loop
			}
		case *node.LeafNode:
			break Loop
		default:
			return nil, 0, fmt.Errorf("urkel: derefNodeID for id %v visited nil node %v", id, n)
		}
	}

	// bd is BitDepth of curPtr's parent
	return curPtr, bd, nil
}

// derefNodePtr dereferences an internal node pointer.
//
// This may result in node database accesses or remote syncing if the node
// is not available locally.
func (c *cache) derefNodePtr(ctx context.Context, id node.ID, ptr *node.Pointer, key node.Key) (node.Node, error) {
	if ptr == nil {
		return nil, nil
	}

	if ptr.Node != nil {
		var refetch bool
		switch n := ptr.Node.(type) {
		case *node.InternalNode:
			// If this is an internal node, check if the leaf node or its value has been
			// evicted. In this case treat it as if we need to re-fetch the node.
			if n.LeafNode != nil && (n.LeafNode.Node == nil || n.LeafNode.Node.(*node.LeafNode).Value == nil) {
				c.removeNode(ptr)
				refetch = true
			}
		case *node.LeafNode:
			// If this is a leaf node, check if the value has been evicted. In this case
			// treat it as if we need to re-fetch the node.
			if n.Value.Value == nil {
				c.removeNode(ptr)
				refetch = true
			}
		}

		if !refetch {
			c.useNode(ptr)
			return ptr.Node, nil
		}
	}

	if !ptr.Clean || ptr.Hash.IsEmpty() {
		return nil, nil
	}

	// First, attempt to fetch from the local node database.
	n, err := c.db.GetNode(c.syncRoot, ptr)
	switch err {
	case nil:
		ptr.Node = n
		// Commit node to cache.
		c.commitNode(ptr)
	case db.ErrNodeNotFound:
		// Node not found in local node database, try the syncer.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.syncerGetNodeTimeout)
		defer cancel()

		if key == nil {
			// Target key is not known, we need to fetch the node.
			if n, err = c.rs.GetNode(ctx, c.syncRoot, id); err != nil {
				return nil, err
			}

			if err = n.Validate(ptr.Hash); err != nil {
				return nil, err
			}

			ptr.Node = n
			// Commit node to cache.
			c.commitNode(ptr)
		} else {
			// If target key is known, we can try prefetching the whole path
			// instead of one node at a time.
			var st *syncer.Subtree
			if st, err = c.rs.GetPath(ctx, c.syncRoot, key, id.BitDepth); err != nil {
				return nil, err
			}
			// Build full node index.
			st.BuildFullNodeIndex()

			// reconstructSubtree commits nodes to cache so a separate commitNode
			// is not needed.
			var newPtr *node.Pointer
			// TODO: Call reconstructSubtree with actual node depth of st! -Matevz
			if newPtr, err = c.reconstructSubtree(ctx, ptr.Hash, st, 0, MaxPrefetchDepth); err != nil {
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
func (c *cache) derefValue(ctx context.Context, v *node.Value) ([]byte, error) {
	// Move the accessed value to the front of the LRU list.
	if v.LRU != nil || v.Value != nil {
		c.useValue(v)
		return v.Value, nil
	}

	if !v.Clean {
		return nil, nil
	}

	return nil, errors.New("urkel: leaf node does not contain value")
}

// prefetch prefetches a given subtree up to the configured prefetch depth.
func (c *cache) prefetch(ctx context.Context, subtreeRoot hash.Hash, subtreePath node.Key, bitDepth node.Depth) (*node.Pointer, error) {
	if c.prefetchDepth == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.syncerPrefetchTimeout)
	defer cancel()

	st, err := c.rs.GetSubtree(ctx, c.syncRoot, node.ID{Path: subtreePath, BitDepth: bitDepth}, c.prefetchDepth)
	switch err {
	case nil:
	case syncer.ErrUnsupported:
		return nil, nil
	default:
		return nil, err
	}
	// Build full node index.
	st.BuildFullNodeIndex()

	ptr, err := c.reconstructSubtree(ctx, subtreeRoot, st, 0, c.prefetchDepth)
	if err != nil {
		return nil, err
	}

	return ptr, nil
}

// reconstructSubtree reconstructs a tree summary received through a
// remote syncer.
func (c *cache) reconstructSubtree(ctx context.Context, rootHash hash.Hash, st *syncer.Subtree, depth node.Depth, maxDepth node.Depth) (*node.Pointer, error) {
	ptr, err := c.doReconstructSummary(st, st.Root, depth, maxDepth)
	if err != nil {
		return nil, err
	}
	if ptr == nil {
		return nil, errors.New("urkel: reconstructed root pointer is nil")
	}

	var d db.NodeDB
	if !c.persistEverythingFromSyncer {
		// Create a no-op database so we can run commit. We don't want to
		// persist everything we retrieve from a remote endpoint as this
		// may be dangerous.
		d, _ = db.NewNopNodeDB()
	} else {
		// Sometimes we do want to persist everything from the syncer.
		// This is used in the cachingclient, for example.
		d = c.db
	}
	batch := d.NewBatch()
	defer batch.Reset()
	subtree := batch.MaybeStartSubtree(nil, depth, ptr)

	syncRootHash, err := doCommit(ctx, c, batch, subtree, depth, ptr)
	if err != nil {
		return nil, err
	}
	if !syncRootHash.Equal(&rootHash) {
		return nil, fmt.Errorf("urkel: syncer returned bad root (expected: %s got: %s)",
			rootHash,
			syncRootHash,
		)
	}
	if err := subtree.Commit(); err != nil {
		return nil, err
	}
	// We must commit even though this is a no-op database in order to fire
	// the on-commit hooks.
	root := node.Root{
		Namespace: c.syncRoot.Namespace,
		Round:     c.syncRoot.Round,
		Hash:      rootHash,
	}
	if err := batch.Commit(root); err != nil {
		return nil, err
	}

	return ptr, nil
}

// doReconstructSummary reconstructs a tree summary received through a
// remote syncer.
func (c *cache) doReconstructSummary(
	st *syncer.Subtree,
	sptr syncer.SubtreePointer,
	depth node.Depth,
	maxDepth node.Depth,
) (*node.Pointer, error) {
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
		nd, err := st.GetFullNodeAt(sptr.Index)
		if err != nil {
			return nil, err
		}

		var ptr *node.Pointer
		switch n := nd.(type) {
		case *node.InternalNode:
			// Internal node, check if we also have full nodes for left/right.
			n.Clean = false

			for _, child := range []**node.Pointer{&n.Left, &n.Right} {
				if *child == nil {
					continue
				}

				if p := st.GetFullNodePointer((*child).Hash); p.Valid {
					var rp *node.Pointer
					rp, err = c.doReconstructSummary(st, p, depth+1, maxDepth)
					if err != nil {
						return nil, err
					}

					*child = rp
				}
			}

			ptr = c.newInternalNodePtr(n)
		case *node.LeafNode:
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

	return c.newInternalNode(s.Label, s.LabelBitLength, leafNode, left, right), nil
}
