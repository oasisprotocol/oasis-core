package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func (t *Tree) doRemove(ctx context.Context, ptr *node.Pointer, depth uint8, key hash.Hash) (*node.Pointer, bool, error) {
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, Depth: depth}, ptr, &key)
	if err != nil {
		return nil, false, err
	}

	switch n := nd.(type) {
	case nil:
		// Remove from nil node.
		return nil, false, nil
	case *node.InternalNode:
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

		lrID := node.ID{Path: key, Depth: depth + 1}
		if nd, err = t.cache.derefNodePtr(ctx, lrID, n.Left, nil); err != nil {
			return nil, false, err
		}

		switch nd.(type) {
		case nil:
			if nd, err = t.cache.derefNodePtr(ctx, lrID, n.Right, nil); err != nil {
				return nil, false, err
			}

			switch nd.(type) {
			case nil:
				// No more children, delete the internal node as well.
				t.cache.removeNode(ptr)
				return nil, true, nil
			case *node.LeafNode:
				// Left is nil, right is leaf, merge nodes back.
				right := n.Right
				n.Right = nil
				t.cache.removeNode(ptr)
				return right, true, nil
			}
		case *node.LeafNode:
			if nd, err = t.cache.derefNodePtr(ctx, lrID, n.Right, nil); err != nil {
				return nil, false, err
			}

			switch nd.(type) {
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
			// No longer eligible for eviction as it is dirty.
			t.cache.rollbackNode(ptr)
		}

		return ptr, changed, nil
	case *node.LeafNode:
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
