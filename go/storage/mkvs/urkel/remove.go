package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func (t *Tree) doRemove(ctx context.Context, ptr *node.Pointer, depth node.DepthType, key node.Key) (*node.Pointer, bool, error) {
	node, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, Depth: depth}, ptr, key)
	if err != nil {
		return nil, false, err
	}

	switch n := nd.(type) {
	case nil:
		// Remove from nil node.
		return nil, false, nil
	case *node.InternalNode:
		// Remove from internal node and recursively collapse the path, if
		// needed.
		var changed bool
		if key.BitLength() == depth {
			n.LeafNode, changed, err = t.doRemove(ctx, n.LeafNode, depth, key)
		} else if key.GetBit(depth) {
			n.Right, changed, err = t.doRemove(ctx, n.Right, depth+1, key)
		} else {
			n.Left, changed, err = t.doRemove(ctx, n.Left, depth+1, key)
		}
		if err != nil {
			return nil, false, err
		}

		lrID := node.NodeID{Path: key, Depth: depth + 1}
		remainingLeaf, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, Depth: depth}, n.LeafNode, nil)
		if err != nil {
			return nil, false, err
		}
		remainingLeft, err := t.cache.derefNodePtr(ctx, lrID, n.Left, nil)
		if err != nil {
			return nil, false, err
		}
		remainingRight, err := t.cache.derefNodePtr(ctx, lrID, n.Right, nil)
		if err != nil {
			return nil, false, err
		}

		// If only one child or leaf node remains collapse it, if it's a leaf.
		// The case when both children are nil and leaf node is nil cannot occur.
		if remainingLeaf != nil && remainingLeft == nil && remainingRight == nil {
			node := n.LeafNode
			n.LeafNode = nil
			t.cache.removeNode(ptr)
			return node, true, nil
		} else if remainingLeaf == nil && remainingLeft != nil && remainingRight == nil {
			switch remainingLeft.(type) {
			case *node.LeafNode:
				node := n.Left
				t.cache.removeNode(ptr)
				return node, true, nil
			}
		} else if remainingLeaf == nil && remainingLeft == nil && remainingRight != nil {
			switch remainingRight.(type) {
			case *node.LeafNode:
				node := n.Right
				t.cache.removeNode(ptr)
				return node, true, nil
			}
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
