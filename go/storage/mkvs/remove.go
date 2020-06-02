package mkvs

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// Implements Tree.
func (t *tree) RemoveExisting(ctx context.Context, key []byte) ([]byte, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return nil, ErrClosed
	}

	// If the key has already been removed locally, don't try to remove it again.
	var entry *pendingEntry
	if !t.withoutWriteLog {
		if entry = t.pendingWriteLog[node.ToMapKey(key)]; entry != nil && entry.value == nil {
			return nil, nil
		}
	}

	// Remember where the path from root to target node ends (will end).
	t.cache.markPosition()

	newRoot, changed, existing, err := t.doRemove(ctx, t.cache.pendingRoot, 0, key, 0)
	if err != nil {
		return nil, err
	}

	// Update the pending write log.
	if !t.withoutWriteLog {
		if entry == nil {
			t.pendingWriteLog[node.ToMapKey(key)] = &pendingEntry{key, nil, changed, nil}
		} else {
			entry.value = nil
		}
	}

	t.cache.setPendingRoot(newRoot)
	return existing, nil
}

// Implements Tree.
func (t *tree) Remove(ctx context.Context, key []byte) error {
	_, err := t.RemoveExisting(ctx, key)
	return err
}

func (t *tree) doRemove(
	ctx context.Context,
	ptr *node.Pointer,
	bitDepth node.Depth,
	key node.Key,
	depth node.Depth,
) (*node.Pointer, bool, []byte, error) {
	if ctx.Err() != nil {
		return nil, false, nil, ctx.Err()
	}

	// Dereference the node, possibly making a remote request.
	nd, err := t.cache.derefNodePtr(ctx, ptr, t.newFetcherSyncGet(key, true))
	if err != nil {
		return nil, false, nil, err
	}

	switch n := nd.(type) {
	case nil:
		// Remove from nil node.
		return nil, false, nil, nil
	case *node.InternalNode:
		// Remove from internal node and recursively collapse the branch, if
		// needed.
		bitLength := bitDepth + n.LabelBitLength

		var changed bool
		var existing []byte
		if key.BitLength() < bitLength {
			// Lookup key is too short for the current n.Label, so it doesn't exist.
			return ptr, false, nil, nil
		} else if key.BitLength() == bitLength {
			n.LeafNode, changed, existing, err = t.doRemove(ctx, n.LeafNode, bitLength, key, depth)
		} else if key.GetBit(bitLength) {
			n.Right, changed, existing, err = t.doRemove(ctx, n.Right, bitLength, key, depth+1)
		} else {
			n.Left, changed, existing, err = t.doRemove(ctx, n.Left, bitLength, key, depth+1)
		}
		if err != nil {
			return nil, false, existing, err
		}

		// Fetch and check the remaining children.
		var remainingLeaf node.Node
		if n.LeafNode != nil {
			// NOTE: The leaf node is always included with the internal node.
			remainingLeaf = n.LeafNode.Node
		}
		remainingLeft, err := t.cache.derefNodePtr(ctx, n.Left, t.newFetcherSyncGet(key, true))
		if err != nil {
			return nil, false, nil, err
		}
		remainingRight, err := t.cache.derefNodePtr(ctx, n.Right, t.newFetcherSyncGet(key, true))
		if err != nil {
			return nil, false, nil, err
		}

		// If exactly one child including LeafNode remains, collapse it.
		if remainingLeaf != nil && remainingLeft == nil && remainingRight == nil {
			ndLeaf := n.LeafNode
			n.LeafNode = nil
			t.pendingRemovedNodes = append(t.pendingRemovedNodes, n)
			t.cache.removeNode(ptr)
			return ndLeaf, true, existing, nil
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
			return nodePtr, true, existing, nil
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

		return ptr, changed, existing, nil
	case *node.LeafNode:
		// Remove from leaf node.
		if n.Key.Equal(key) {
			t.pendingRemovedNodes = append(t.pendingRemovedNodes, n)
			t.cache.removeNode(ptr)
			return nil, true, n.Value, nil
		}

		return ptr, false, nil, nil
	default:
		panic(fmt.Sprintf("mkvs: unknown node type: %+v", n))
	}
}
