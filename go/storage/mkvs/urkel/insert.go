package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func (t *Tree) doInsert(ctx context.Context, ptr *node.Pointer, depth uint8, key hash.Hash, val []byte) (*node.Pointer, bool, error) {
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, Depth: depth}, ptr, nil)
	if err != nil {
		return nil, false, err
	}

	switch n := nd.(type) {
	case nil:
		// Insert into nil node, create a new leaf node.
		return t.cache.newLeafNode(key, val), false, nil
	case *node.InternalNode:
		var existed bool
		if getKeyBit(key, depth) {
			n.Right, existed, err = t.doInsert(ctx, n.Right, depth+1, key, val)
		} else {
			n.Left, existed, err = t.doInsert(ctx, n.Left, depth+1, key, val)
		}
		if err != nil {
			return nil, false, err
		}

		if !n.Left.IsClean() || !n.Right.IsClean() {
			n.Clean = false
			ptr.Clean = false
			// No longer eligible for eviction as it is dirty.
			t.cache.rollbackNode(ptr)
		}

		return ptr, existed, nil
	case *node.LeafNode:
		// If the key matches, we can just update the value.
		if n.Key.Equal(&key) {
			if n.Value.Equal(val) {
				return ptr, true, nil
			}

			t.cache.removeValue(n.Value)
			n.Value = t.cache.newValue(val)
			n.Clean = false
			ptr.Clean = false
			// No longer eligible for eviction as it is dirty.
			t.cache.rollbackNode(ptr)
			return ptr, true, nil
		}

		existingBit := getKeyBit(n.Key, depth)
		newBit := getKeyBit(key, depth)

		var left, right *node.Pointer
		if existingBit != newBit {
			// No bit collision at this depth, create an internal node with
			// two leaves.
			if existingBit {
				left = t.cache.newLeafNode(key, val)
				right = ptr
			} else {
				left = ptr
				right = t.cache.newLeafNode(key, val)
			}
		} else {
			// Bit collision at this depth.
			if existingBit {
				left = nil
				right, _, err = t.doInsert(ctx, ptr, depth+1, key, val)
			} else {
				left, _, err = t.doInsert(ctx, ptr, depth+1, key, val)
				right = nil
			}
			if err != nil {
				return nil, false, err
			}
		}

		return t.cache.newInternalNode(left, right), false, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
