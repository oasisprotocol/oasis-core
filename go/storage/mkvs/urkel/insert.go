package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

type insertResult struct {
	newRoot      *node.Pointer
	insertedLeaf *node.Pointer
	existed      bool
}

func (t *Tree) doInsert(ctx context.Context, ptr *node.Pointer, depth uint8, key hash.Hash, val []byte) (insertResult, error) {
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, Depth: depth}, ptr, nil)
	if err != nil {
		return insertResult{}, err
	}

	switch n := nd.(type) {
	case nil:
		// Insert into nil node, create a new leaf node.
		newLeaf := t.cache.newLeafNode(key, val)
		result := insertResult{
			newRoot:      newLeaf,
			insertedLeaf: newLeaf,
			existed:      false,
		}
		return result, nil
	case *node.InternalNode:
		var result insertResult

		goRight := getKeyBit(key, depth)
		if goRight {
			result, err = t.doInsert(ctx, n.Right, depth+1, key, val)
		} else {
			result, err = t.doInsert(ctx, n.Left, depth+1, key, val)
		}
		if err != nil {
			return insertResult{}, err
		}

		if goRight {
			n.Right = result.newRoot
		} else {
			n.Left = result.newRoot
		}

		if !n.Left.IsClean() || !n.Right.IsClean() {
			n.Clean = false
			ptr.Clean = false
			// No longer eligible for eviction as it is dirty.
			t.cache.rollbackNode(ptr)
		}

		result.newRoot = ptr
		return result, nil
	case *node.LeafNode:
		// If the key matches, we can just update the value.
		if n.Key.Equal(&key) {
			if n.Value.Equal(val) {
				return insertResult{
					newRoot:      ptr,
					insertedLeaf: ptr,
					existed:      true,
				}, nil
			}

			t.cache.removeValue(n.Value)
			n.Value = t.cache.newValue(val)
			n.Clean = false
			ptr.Clean = false
			// No longer eligible for eviction as it is dirty.
			t.cache.rollbackNode(ptr)
			return insertResult{
				newRoot:      ptr,
				insertedLeaf: ptr,
				existed:      true,
			}, nil
		}

		existingBit := getKeyBit(n.Key, depth)
		newBit := getKeyBit(key, depth)

		var left, right *node.Pointer
		var result insertResult
		if existingBit != newBit {
			// No bit collision at this depth, create an internal node with
			// two leaves.
			if existingBit {
				left = t.cache.newLeafNode(key, val)
				right = ptr
				result.insertedLeaf = left
			} else {
				left = ptr
				right = t.cache.newLeafNode(key, val)
				result.insertedLeaf = right
			}
		} else {
			// Bit collision at this depth.
			result, err = t.doInsert(ctx, ptr, depth+1, key, val)
			if existingBit {
				left = nil
				right = result.newRoot
			} else {
				left = result.newRoot
				right = nil
			}
			if err != nil {
				return insertResult{}, err
			}
		}

		return insertResult{
			newRoot:      t.cache.newInternalNode(left, right),
			insertedLeaf: result.insertedLeaf,
			existed:      false,
		}, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
