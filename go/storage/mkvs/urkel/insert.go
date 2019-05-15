package urkel

import (
	"context"
	"fmt"
	"hash"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

type insertResult struct {
	newRoot      *node.Pointer
	insertedLeaf *node.Pointer
	existed      bool
}

func (t *Tree) doInsert(ctx context.Context, ptr *node.Pointer, depth node.DepthType, key node.Key, val []byte) (insertResult, error) {
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

		if key.BitLength() == depth {
			// Key to insert ends at this depth. Add it as a LeafNode reference
			// to the existing internal node.
			result, err = t.doInsert(ctx, n.LeafNode, depth, key, val)
		} else if key.GetBit(depth) {
			// Otherwise, insert recursively based on a bit value.
			result, err = t.doInsert(ctx, n.Right, depth+1, key, val)
		} else {
			result, err = t.doInsert(ctx, n.Left, depth+1, key, val)
		}
		if err != nil {
			return insertResult{}, err
		}

		if key.BitLength() == depth {
			n.LeafNode = result.newRoot
		}
		} else if key.GetBit(depth) {
			n.Right = result.newRoot
		} else {
			n.Left = result.newRoot
		}

		if !n.LeafNode.IsClean() || !n.Left.IsClean() || !n.Right.IsClean() {
			n.Clean = false
			ptr.Clean = false
			// No longer eligible for eviction as it is dirty.
			t.cache.rollbackNode(ptr)
		}

		result.newRoot = ptr
		return result, nil
	case *node.LeafNode:
		// If the key matches, we can just update the value.
		if n.Key.Equal(key) {
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

		// If the key mismatches, three cases are possible:
		var leafNode, left, right *node.Pointer
		var existingBit bool
		if key.BitLength() == depth {
			// Case 1: key is a prefix of leafNode.Key.
			leafNode = t.cache.newLeafNode(key, val)
			result.insertedLeaf = leafNode
			if n.Key.GetBit(depth) {
				left = nil
				right = ptr
			} else {
				left = ptr
				right = nil
			}
		} else if n.Key.BitLength() == depth {
			// Case 2: leafNode.Key is a prefix of key.
			leafNode = ptr
			if key.GetBit(depth) {
				left = nil
				right = t.cache.newLeafNode(key, val)
				result.insertedLeaf = right
			} else {
				left = t.cache.newLeafNode(key, val)
				right = nil
				result.insertedLeaf = left
			}
		} else {
			// Case 3: length of common prefix of leafNode.Key and key is
			//         shorter than len(n.Key) and len(key).
			existingBit = n.Key.GetBit(depth)
			newBit := key.GetBit(depth)

			if existingBit != newBit {
				// Bits mismatched at this depth, create an internal node with
				// two leaves.
				if existingBit {
					left = t.cache.newLeafNode(key, val)
					right = ptr
				} else {
					left = ptr
					right = t.cache.newLeafNode(key, val)
				}
			} else {
				// Bits matched at this depth. Go into recursion and then create
				// an internal node with two leaves.
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
		}

		return insertResult{
			newRoot:      t.cache.newInternalNode(leafNode, left, right),
			insertedLeaf: result.insertedLeaf,
			existed:      false,
		}, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
