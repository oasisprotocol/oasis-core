package mkvs

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var errRemoveLocked = errors.New("mkvs: tried to remove locked pointer")

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

	// Maximum capacity of internal nodes.
	nodeCapacity uint64
	// Maximum capacity of leaf values.
	valueCapacity uint64
	// Persist all the nodes and values we obtain from the remote syncer?
	persistEverythingFromSyncer bool

	lruInternal    *list.List
	lruInternalPos *list.Element
	lruLeaf        *list.List
	lruLeafPos     *list.Element
}

// MaxPrefetchDepth is the maximum depth of the prefeteched tree.
const MaxPrefetchDepth = 255

func newCache(ndb db.NodeDB, rs syncer.ReadSyncer, rootType node.RootType) *cache {
	c := &cache{
		db:                          ndb,
		rs:                          rs,
		lruInternal:                 list.New(),
		lruLeaf:                     list.New(),
		persistEverythingFromSyncer: false,
		valueCapacity:               16 * 1024 * 1024,
		nodeCapacity:                5000,
	}
	// By default the sync root is an empty root.
	c.syncRoot.Empty()
	c.syncRoot.Type = rootType

	return c
}

func (c *cache) close() {
	// Clear references.
	c.db = nil
	c.rs = nil
	c.pendingRoot = nil
	c.lruInternal = nil
	c.lruInternalPos = nil
	c.lruLeaf = nil
	c.lruLeafPos = nil

	// Reset sync root.
	c.syncRoot = node.Root{}

	// Reset statistics.
	c.valueSize = 0
	c.internalNodeCount = 0
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
		Value: val,
	})
}

func (c *cache) newInternalNodePtr(n *node.InternalNode) *node.Pointer {
	return &node.Pointer{
		Node: n,
	}
}

func (c *cache) newInternalNode(label node.Key, labelBitLength node.Depth, leafNode, left, right *node.Pointer) *node.Pointer {
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
	switch ptr.Node.(type) {
	case *node.InternalNode:
		c.lruInternal.MoveToFront(ptr.LRU)
	case *node.LeafNode:
		c.lruLeaf.MoveToFront(ptr.LRU)
	}
}

// markPosition marks the current LRU queue positions as the ones before
// any nodes are visited. Any new nodes committed into the cache after
// this is called will be inserted after the marked position.
//
// This makes it possible to keep the path from the root to the derefed
// node in the cache instead of evicting it.
func (c *cache) markPosition() {
	c.lruInternalPos = c.lruInternal.Front()
	c.lruLeafPos = c.lruLeaf.Front()
}

func (c *cache) tryCommitNode(ptr, lockedPtr *node.Pointer) error {
	if !ptr.IsClean() {
		panic("mkvs: commitNode called on dirty node")
	}
	if ptr == nil || ptr.Node == nil {
		return nil
	}
	if ptr.LRU != nil {
		c.useNode(ptr)
		return nil
	}

	// Evict nodes till there is enough capacity.
	switch n := ptr.Node.(type) {
	case *node.InternalNode:
		if c.nodeCapacity > 0 && c.internalNodeCount+1 > c.nodeCapacity {
			if err := c.tryEvictInternal(1, lockedPtr); err != nil {
				return err
			}
		}

		if c.lruInternalPos != nil {
			ptr.LRU = c.lruInternal.InsertAfter(ptr, c.lruInternalPos)
		} else {
			ptr.LRU = c.lruInternal.PushFront(ptr)
		}
		c.internalNodeCount++
	case *node.LeafNode:
		valueSize := n.Size()

		if c.valueCapacity > 0 && c.valueSize+valueSize > c.valueCapacity {
			if err := c.tryEvictLeaf(valueSize, lockedPtr); err != nil {
				return err
			}
		}

		if c.lruLeafPos != nil {
			ptr.LRU = c.lruLeaf.InsertAfter(ptr, c.lruLeafPos)
		} else {
			ptr.LRU = c.lruLeaf.PushFront(ptr)
		}
		c.valueSize += valueSize
	}
	return nil
}

// commitNode makes the node eligible for eviction.
func (c *cache) commitNode(ptr *node.Pointer) {
	_ = c.tryCommitNode(ptr, nil)
}

// rollbackNode marks a tree node as no longer being eligible for
// eviction due to it becoming dirty.
func (c *cache) rollbackNode(ptr *node.Pointer) {
	if ptr.LRU == nil {
		// Node has not yet been committed to cache.
		return
	}

	switch n := ptr.Node.(type) {
	case *node.InternalNode:
		if c.lruInternalPos == ptr.LRU {
			c.lruInternalPos = nil
		}
		c.lruInternal.Remove(ptr.LRU)
		c.internalNodeCount--
	case *node.LeafNode:
		if c.lruLeafPos == ptr.LRU {
			c.lruLeafPos = nil
		}
		c.lruLeaf.Remove(ptr.LRU)
		c.valueSize -= n.Size()
	}

	ptr.LRU = nil
}

func (c *cache) tryRemoveNode(ptr, lockedPtr *node.Pointer) error {
	if lockedPtr != nil && lockedPtr == ptr {
		return errRemoveLocked
	}
	if ptr.LRU == nil {
		// Node has not yet been committed to cache.
		return nil
	}

	switch n := ptr.Node.(type) {
	case *node.InternalNode:
		// Remove leaf node and subtrees first.
		if n.LeafNode != nil && n.LeafNode.Node != nil {
			if err := c.tryRemoveNode(n.LeafNode, lockedPtr); err != nil {
				return err
			}
			n.LeafNode = nil
		}
		if n.Left != nil && n.Left.Node != nil {
			if err := c.tryRemoveNode(n.Left, lockedPtr); err != nil {
				return err
			}
			n.Left = nil
		}
		if n.Right != nil && n.Right.Node != nil {
			if err := c.tryRemoveNode(n.Right, lockedPtr); err != nil {
				return err
			}
			n.Right = nil
		}

		if c.lruInternalPos == ptr.LRU {
			c.lruInternalPos = nil
		}
		c.lruInternal.Remove(ptr.LRU)
		c.internalNodeCount--
	case *node.LeafNode:
		if c.lruLeafPos == ptr.LRU {
			c.lruLeafPos = nil
		}
		c.lruLeaf.Remove(ptr.LRU)
		c.valueSize -= n.Size()
	}

	ptr.Node = nil
	ptr.LRU = nil
	return nil
}

// removeNode removes a tree node.
func (c *cache) removeNode(ptr *node.Pointer) {
	_ = c.tryRemoveNode(ptr, nil)
}

// tryEvictLeaf tries to evict leaf nodes from the cache.
func (c *cache) tryEvictLeaf(targetCapacity uint64, lockedPtr *node.Pointer) error {
	for c.lruLeaf.Len() > 0 && c.valueSize+targetCapacity > c.valueCapacity {
		elem := c.lruLeaf.Back()
		n := elem.Value.(*node.Pointer)
		if !n.Clean {
			panic(fmt.Errorf("mkvs: tried to evict dirty node %v", n))
		}
		if err := c.tryRemoveNode(n, lockedPtr); err != nil {
			return err
		}
	}
	return nil
}

// tryEvictInternal tries to evict internal nodes from the cache.
func (c *cache) tryEvictInternal(targetCapacity uint64, lockedPtr *node.Pointer) error {
	for c.lruInternal.Len() > 0 && c.internalNodeCount+targetCapacity > c.nodeCapacity {
		elem := c.lruInternal.Back()
		n := elem.Value.(*node.Pointer)
		if !n.Clean {
			panic(fmt.Errorf("mkvs: tried to evict dirty node %v", n))
		}
		if err := c.tryRemoveNode(n, lockedPtr); err != nil {
			return err
		}
	}
	return nil
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

	c.useNode(ptr)

	if ptr.Node != nil {
		var refetch bool
		switch n := ptr.Node.(type) {
		case *node.InternalNode:
			// If this is an internal node, check if the leaf node has been evicted.
			// In this case treat it as if we need to re-fetch the node.
			if n.LeafNode != nil && n.LeafNode.Node == nil {
				c.removeNode(ptr)
				refetch = true
			}
		}

		if !refetch {
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

		if ptr.Node == nil {
			return nil, fmt.Errorf("mkvs: received result did not contain node (or cache too small)")
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
		return fmt.Errorf("mkvs: got proof for unexpected root (%s)", proof.UntrustedRoot)
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
		batch, err = c.db.NewBatch(c.syncRoot, c.syncRoot.Version, false)
		if err != nil {
			return fmt.Errorf("mkvs: failed to create batch: %w", err)
		}
		dbSubtree = batch.MaybeStartSubtree(nil, 0, subtree)
	}

	var commitNode func(*node.Pointer) error
	commitNode = func(p *node.Pointer) error {
		if p == nil || p.Node == nil {
			return nil
		}

		// Try to commit the node. If we fail this means that there is not enough
		// space in the cache to keep the node that we are trying to dereference.
		if err := c.tryCommitNode(p, ptr); err != nil {
			// Failed to commit, make sure to not keep the subtree in memory.
			p.Node = nil
			return err
		}

		// Commit all children.
		if n, ok := p.Node.(*node.InternalNode); ok {
			if err := commitNode(n.Left); err != nil {
				return err
			}
			if err := commitNode(n.Right); err != nil {
				return err
			}
		}

		// Persist synced nodes to local node database when configured. We assume that
		// in this case the node database backend is a cache-only backend and does not
		// perform any subtree aggregation.
		if c.persistEverythingFromSyncer {
			_ = dbSubtree.PutNode(0, p)
		}
		return nil
	}

	if err := c.MergeVerifiedSubtree(ctx, dstPtr, subtree, commitNode); err != nil {
		if err == errRemoveLocked {
			// Cache is too small, ignore.
			return nil
		}
		return err
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

	return nil
}
