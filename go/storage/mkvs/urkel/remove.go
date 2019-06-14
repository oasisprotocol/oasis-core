package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

func (t *Tree) doRemove(ctx context.Context, ptr *internal.Pointer, depth uint8, key hash.Hash) (*internal.Pointer, bool, error) {
	node, err := t.cache.derefNodePtr(ctx, internal.NodeID{Path: key, Depth: depth}, ptr, &key)
	if err != nil {
		return nil, false, err
	}

	switch n := node.(type) {
	case nil:
		// Remove from nil node.
		return nil, false, nil
	case *internal.InternalNode:
		// Remove from internal node.
		var changed bool
		if getKeyBit(key, depth) {
			n.Right, changed, err = t.doRemove(ctx, n.Right, depth+1, key)
		} else {
			n.Left, changed, err = t.doRemove(ctx, n.Left, depth+1, key)
		}
		if err != nil {
			return nil, false, err
		}

		lrID := internal.NodeID{Path: key, Depth: depth + 1}
		if node, err = t.cache.derefNodePtr(ctx, lrID, n.Left, nil); err != nil {
			return nil, false, err
		}

		switch node.(type) {
		case nil:
			if node, err = t.cache.derefNodePtr(ctx, lrID, n.Right, nil); err != nil {
				return nil, false, err
			}

			switch node.(type) {
			case nil:
				// No more children, delete the internal node as well.
				t.cache.removeNode(ptr)
				return nil, true, nil
			case *internal.LeafNode:
				// Left is nil, right is leaf, merge nodes back.
				right := n.Right
				n.Right = nil
				t.cache.removeNode(ptr)
				return right, true, nil
			}
		case *internal.LeafNode:
			if node, err = t.cache.derefNodePtr(ctx, lrID, n.Right, nil); err != nil {
				return nil, false, err
			}

			switch node.(type) {
			case nil:
				// Right is nil, left is leaf, merge nodes back.
				left := n.Left
				n.Left = nil
				t.cache.removeNode(ptr)
				return left, true, nil
			}
		}

		if changed {
			n.Clean = false
			ptr.Clean = false
		}

		return ptr, changed, nil
	case *internal.LeafNode:
		// Remove from leaf node.
		if n.Key.Equal(&key) {
			t.cache.removeNode(ptr)
			return nil, true, nil
		}

		return ptr, false, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
