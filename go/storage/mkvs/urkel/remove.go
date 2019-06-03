package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

func (t *Tree) doRemove(ctx context.Context, ptr *internal.Pointer, depth internal.DepthType, key internal.Key) (*internal.Pointer, bool, error) {
	node, err := t.cache.derefNodePtr(ctx, internal.NodeID{Path: key, Depth: depth}, ptr, key)
	if err != nil {
		return nil, false, err
	}

	switch n := node.(type) {
	case nil:
		// Remove from nil node.
		return nil, false, nil
	case *internal.InternalNode:
		// Remove from internal node and recursively collapse the path, if
		// needed.
		var changed bool
		if key.BitLength() == int(depth) {
			n.LeafNode, changed, err = t.doRemove(ctx, n.LeafNode, depth, key)
		} else if key.GetBit(depth) {
			n.Right, changed, err = t.doRemove(ctx, n.Right, depth+1, key)
		} else {
			n.Left, changed, err = t.doRemove(ctx, n.Left, depth+1, key)
		}
		if err != nil {
			return nil, false, err
		}

		lrID := internal.NodeID{Path: key, Depth: depth + 1}
		remainingLeaf, err := t.cache.derefNodePtr(ctx, internal.NodeID{Path: key, Depth: depth}, n.LeafNode, nil)
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
		if remainingLeaf != nil && remainingLeft == nil && remainingRight == nil {
			return n.LeafNode, true, nil
		} else if remainingLeaf == nil && remainingLeft != nil && remainingRight == nil {
			switch remainingLeft.(type) {
			case *internal.LeafNode:
				return n.Left, true, nil
			}
		} else if remainingLeaf == nil && remainingLeft == nil && remainingRight != nil {
			switch remainingRight.(type) {
			case *internal.LeafNode:
				return n.Right, true, nil
			}
		}

		// Two or more children including LeafNode remain, just mark dirty bit.
		if changed {
			n.Clean = false
			ptr.Clean = false
		}

		return ptr, changed, nil
	case *internal.LeafNode:
		// Remove from leaf node.
		if n.Key.Equal(key) {
			t.cache.tryRemoveNode(ptr)
			return nil, true, nil
		}

		return ptr, false, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
