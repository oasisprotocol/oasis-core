package urkel

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	db "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

// cache handles the in-memory tree cache.
type cache struct {
	sync.Mutex
	syncer.ProofVerifier
	syncer.SubtreeMerger

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
	// Persist all the nodes and values we obtain from the remote syncer?
	persistEverythingFromSyncer bool

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

// readSyncFetcher is a function that is used to fetch proofs from a remote
// tree via the ReadSyncer interface.
type readSyncFetcher func(context.Context, *node.Pointer, syncer.ReadSyncer) (*syncer.Proof, error)

// derefNodePtr dereferences an internal node pointer.
//
// This may result in node database accesses or remote syncing if the node
// is not available locally.
func (c *cache) derefNodePtr(
	ctx context.Context,
	ptr *node.Pointer,
	fetcher readSyncFetcher,
) (node.Node, error) {
	if ptr == nil {
		return nil, nil
	}

	// TODO: Simplify this eviction mess.
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
		// Node not found in local node database, try the syncer if available.
		if c.rs == syncer.NopReadSyncer {
			return nil, err
		}

		if err = c.remoteSync(ctx, ptr, fetcher); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	return ptr.Node, nil
}

// remoteSync performs a remote sync with the configured remote syncer.
func (c *cache) remoteSync(ctx context.Context, ptr *node.Pointer, fetcher readSyncFetcher) error {
	proof, err := fetcher(ctx, ptr, c.rs)
	if err != nil {
		return err
	}

	// The proof can be for one of two hashes: i) it is either for ptr.Hash in case
	// all the nodes are only contained in the subtree below ptr, or ii) it is for
	// the c.syncRoot.Hash in case it contains nodes outside the subtree.
	var dstPtr *node.Pointer
	var expectedRoot hash.Hash
	switch {
	case proof.UntrustedRoot.Equal(&ptr.Hash):
		dstPtr = ptr
		expectedRoot = ptr.Hash
	case proof.UntrustedRoot.Equal(&c.syncRoot.Hash):
		dstPtr = c.pendingRoot
		expectedRoot = c.syncRoot.Hash
	default:
		// Proof is for an unknown root.
		return fmt.Errorf("urkel: got proof for unexpected root (%s)", proof.UntrustedRoot)
	}

	// Verify proof.
	subtree, err := c.VerifyProof(ctx, expectedRoot, proof)
	if err != nil {
		return err
	}

	// Merge resulting nodes.
	var batch db.Batch
	var dbSubtree db.Subtree
	if c.persistEverythingFromSyncer {
		// NOTE: This is a dummy batch, we assume that the node database backend is a
		//       cache-only backend and does not care about correct values.
		batch = c.db.NewBatch(c.syncRoot.Namespace, c.syncRoot.Round, c.syncRoot)
		dbSubtree = batch.MaybeStartSubtree(nil, 0, subtree)
	}
	var commitNode func(*node.Pointer)
	commitNode = func(p *node.Pointer) {
		if p == nil || p.Node == nil {
			return
		}

		// Commit all children.
		switch n := p.Node.(type) {
		case *node.InternalNode:
			commitNode(n.Left)
			commitNode(n.Right)
		case *node.LeafNode:
			c.commitValue(n.Value)
		}

		// Commit the node itself.
		c.commitNode(p)
		// Persist synced nodes to local node database when configured. We assume that
		// in this case the node database backend is a cache-only backend and does not
		// perform any subtree aggregation.
		if c.persistEverythingFromSyncer {
			_ = dbSubtree.PutNode(0, p)
		}
	}
	// Persist synced nodes to local node database when configured.
	if c.persistEverythingFromSyncer {
		if err := dbSubtree.Commit(); err != nil {
			return err
		}
		if err := batch.Commit(c.syncRoot); err != nil {
			return err
		}
	}

	if err := c.MergeVerifiedSubtree(ctx, dstPtr, subtree, commitNode); err != nil {
		return err
	}
	return nil
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
