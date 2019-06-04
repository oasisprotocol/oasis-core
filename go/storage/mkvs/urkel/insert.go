package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

// doInsert is a recursive function for inserting a key into the urkel tree.
func (t *Tree) doInsert(ctx context.Context, ptr *internal.Pointer, depth internal.DepthType, key internal.Key, val []byte) (*internal.Pointer, bool, error) {
	//	fmt.Println("inserting key:", string(key), "depth:", depth)
	node, err := t.cache.derefNodePtr(ctx, internal.NodeID{Path: key, Depth: depth}, ptr, nil)
	if err != nil {
		return nil, false, err
	}

	switch n := node.(type) {
	case nil:
		// Insert into nil node, create a new leaf node.
		return t.cache.newLeafNode(key, val), false, nil
	case *internal.InternalNode:
		var existed bool
		if key.BitLength() == depth {
			// Key to insert ends at this depth. Add it as a LeafNode reference
			// to the existing internal node.
			n.LeafNode, existed, err = t.doInsert(ctx, n.LeafNode, depth, key, val)
		} else if key.GetBit(depth) {
			// Otherwise, insert recursively based on a bit value.
			n.Right, existed, err = t.doInsert(ctx, n.Right, depth+1, key, val)
		} else {
			n.Left, existed, err = t.doInsert(ctx, n.Left, depth+1, key, val)
		}
		if err != nil {
			return nil, false, err
		}

		if !n.LeafNode.IsClean() || !n.Left.IsClean() || !n.Right.IsClean() {
			n.Clean = false
			ptr.Clean = false
		}

		return ptr, existed, nil
	case *internal.LeafNode:
		// If the key matches, we can just update the value.
		if n.Key.Equal(key) {
			if n.Value.Equal(val) {
				return ptr, true, nil
			}

			t.cache.removeValue(n.Value)
			n.Value = t.cache.newValue(val)
			n.Clean = false
			ptr.Clean = false
			return ptr, true, nil
		}

		// If the key mismatches, three cases are possible:
		var leafNode, left, right *internal.Pointer
		var existingBit bool
		if key.BitLength() == depth {
			// Case 1: key is a prefix of n.Key
			leafNode = t.cache.newLeafNode(key, val)
			if n.Key.GetBit(depth) {
				left = nil
				right = ptr
			} else {
				left = ptr
				right = nil
			}
		} else if n.Key.BitLength() == depth {
			// Case 2: n.Key is a prefix of key
			leafNode = ptr
			if key.GetBit(depth) {
				left = nil
				right = t.cache.newLeafNode(key, val)
			} else {
				left = t.cache.newLeafNode(key, val)
				right = nil
			}
		} else {
			// Case 3: length of common prefix of n.Key and key is shorter than
			//         len(n.Key) and len(key)
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

		return t.cache.newInternalNode(leafNode, left, right), false, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
