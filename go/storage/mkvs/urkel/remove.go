package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func (t *Tree) doRemove(ctx context.Context, ptr *node.Pointer, bitDepth node.Depth, key node.Key, depth node.Depth) (*node.Pointer, bool, error) {
	// NB: bitDepth is the bit depth of parent of ptr, so add one bit to fetch the
	// node corresponding to key.
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, BitDepth: bitDepth + 1}, ptr, key)
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
		var changed bool
		if key.BitLength() == bitDepth+n.LabelBitLength {
			n.LeafNode, changed, err = t.doRemove(ctx, n.LeafNode, bitDepth+n.LabelBitLength, key, depth)
		} else if key.GetBit(bitDepth + n.LabelBitLength) {
			n.Right, changed, err = t.doRemove(ctx, n.Right, bitDepth+n.LabelBitLength, key, depth+1)
		} else {
			n.Left, changed, err = t.doRemove(ctx, n.Left, bitDepth+n.LabelBitLength, key, depth+1)
		}
		if err != nil {
			return nil, false, err
		}

		// Fetch and check the remaining children.
		remainingLeaf, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, BitDepth: bitDepth + n.LabelBitLength}, n.LeafNode, nil)
		if err != nil {
			return nil, false, err
		}
		keyPrefix, _ := key.Split(bitDepth+n.LabelBitLength, key.BitLength())
		remainingLeft, err := t.cache.derefNodePtr(ctx, node.ID{Path: keyPrefix.AppendBit(bitDepth+n.LabelBitLength, false), BitDepth: bitDepth + n.LabelBitLength + 1}, n.Left, nil)
		if err != nil {
			return nil, false, err
		}
		remainingRight, err := t.cache.derefNodePtr(ctx, node.ID{Path: keyPrefix.AppendBit(bitDepth+n.LabelBitLength, true), BitDepth: bitDepth + n.LabelBitLength + 1}, n.Right, nil)
		if err != nil {
			return nil, false, err
		}

		// If exactly one child including LeafNode remains, collapse it.
		if remainingLeaf != nil && remainingLeft == nil && remainingRight == nil {
			ndLeaf := n.LeafNode
			n.LeafNode = nil
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
				inode.Clean = false
				nodePtr.Clean = false
			}

			t.cache.removeNode(ptr)
			return nodePtr, true, nil
		}

		// Two or more children including LeafNode remain, just mark dirty bit.
		if changed {
			n.Clean = false
			ptr.Clean = false
			// No longer eligible for eviction as it is dirty.
			t.cache.rollbackNode(ptr)
		}

		return ptr, changed, nil
	case *node.LeafNode:
		// Remove from leaf node.
		if n.Key.Equal(key) {
			t.cache.removeNode(ptr)
			return nil, true, nil
		}

		return ptr, false, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
