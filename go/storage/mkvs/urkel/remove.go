package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
)

// Remove removes a key from the tree.
func (t *Tree) Remove(ctx context.Context, key []byte) error {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return ErrClosed
	}

	var changed bool
	newRoot, changed, err := t.doRemove(ctx, t.cache.pendingRoot, 0, key, 0)
	if err != nil {
		return err
	}

	// Update the pending write log.
	entry := t.pendingWriteLog[node.ToMapKey(key)]
	if entry == nil {
		t.pendingWriteLog[node.ToMapKey(key)] = &pendingEntry{key, nil, changed, nil}
	} else {
		entry.value = nil
	}

	t.cache.setPendingRoot(newRoot)
	return nil
}

func (t *Tree) doRemove(
	ctx context.Context,
	ptr *node.Pointer,
	bitDepth node.Depth,
	key node.Key,
	depth node.Depth,
) (*node.Pointer, bool, error) {
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}

	// Dereference the node, possibly making a remote request.
	nd, err := t.cache.derefNodePtr(ctx, ptr, t.newFetcherSyncGet(key, true))
	if err != nil {
		return nil, false, err
	}

	switch n := nd.(type) {
	case nil:
		// Remove from nil node.
		return nil, false, nil
	case *node.InternalNode:
		// Remove from internal node and recursively collapse the branch, if
		// needed.
		bitLength := bitDepth + n.LabelBitLength

		var changed bool
		if key.BitLength() == bitLength {
			n.LeafNode, changed, err = t.doRemove(ctx, n.LeafNode, bitLength, key, depth)
		} else if key.GetBit(bitLength) {
			n.Right, changed, err = t.doRemove(ctx, n.Right, bitLength, key, depth+1)
		} else {
			n.Left, changed, err = t.doRemove(ctx, n.Left, bitLength, key, depth+1)
		}
		if err != nil {
			return nil, false, err
		}

		// Fetch and check the remaining children.
		var remainingLeaf node.Node
		if n.LeafNode != nil {
			// NOTE: The leaf node is always included with the internal node.
			remainingLeaf = n.LeafNode.Node
		}
		remainingLeft, err := t.cache.derefNodePtr(ctx, n.Left, t.newFetcherSyncGet(key, true))
		if err != nil {
			return nil, false, err
		}
		remainingRight, err := t.cache.derefNodePtr(ctx, n.Right, t.newFetcherSyncGet(key, true))
		if err != nil {
			return nil, false, err
		}

		// If exactly one child including LeafNode remains, collapse it.
		if remainingLeaf != nil && remainingLeft == nil && remainingRight == nil {
			ndLeaf := n.LeafNode
			n.LeafNode = nil
			t.pendingRemovedNodes = append(t.pendingRemovedNodes, n)
			t.cache.removeNode(ptr)
			return ndLeaf, true, nil
		} else if remainingLeaf == nil && (remainingLeft == nil || remainingRight == nil) {
			var nodePtr *node.Pointer
			var ndChild node.Node
			if remainingLeft != nil {
				nodePtr = n.Left
				n.Left = nil
				ndChild = remainingLeft
			} else {
				nodePtr = n.Right
				n.Right = nil
				ndChild = remainingRight
			}

			// If child is an internal node, also fix the label.
			switch inode := ndChild.(type) {
			case *node.InternalNode:
				inode.Label = n.Label.Merge(n.LabelBitLength, inode.Label, inode.LabelBitLength)
				inode.LabelBitLength += n.LabelBitLength
				if inode.Clean {
					// Node was clean so old node is eligible for removal.
					t.pendingRemovedNodes = append(t.pendingRemovedNodes, inode.ExtractUnchecked())
				}
				inode.Clean = false
				nodePtr.Clean = false
				// No longer eligible for eviction as it is dirty.
				t.cache.rollbackNode(nodePtr)
			}

			t.pendingRemovedNodes = append(t.pendingRemovedNodes, n)
			t.cache.removeNode(ptr)
			return nodePtr, true, nil
		}

		// Two or more children including LeafNode remain, just mark dirty bit.
		if changed {
			if n.Clean {
				// Node was clean so old node is eligible for removal.
				t.pendingRemovedNodes = append(t.pendingRemovedNodes, n.ExtractUnchecked())
			}

			n.Clean = false
			ptr.Clean = false
			// No longer eligible for eviction as it is dirty.
			t.cache.rollbackNode(ptr)
		}

		return ptr, changed, nil
	case *node.LeafNode:
		// Remove from leaf node.
		if n.Key.Equal(key) {
			t.pendingRemovedNodes = append(t.pendingRemovedNodes, n)
			t.cache.removeNode(ptr)
			return nil, true, nil
		}

		return ptr, false, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
