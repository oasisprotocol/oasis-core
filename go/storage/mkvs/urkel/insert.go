package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

type insertResult struct {
	newRoot      *node.Pointer
	insertedLeaf *node.Pointer
	existed      bool
}

func (t *Tree) doInsert(ctx context.Context, ptr *node.Pointer, bitDepth node.Depth, key node.Key, val []byte, depth node.Depth) (insertResult, error) {
	// NB: bitDepth is the bit depth of parent of ptr, so add one bit to fetch
	// the node corresponding to key.
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, BitDepth: bitDepth + 1}, ptr, nil)
	if err != nil {
		return insertResult{}, err
	}

	_, keyRemainder := key.Split(bitDepth, key.BitLength())

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
		cpLength := n.Label.CommonPrefixLen(n.LabelBitLength, keyRemainder, key.BitLength()-bitDepth)
		var result insertResult

		if cpLength == n.LabelBitLength {
			bitLength := bitDepth + n.LabelBitLength

			// The current part of key matched the node's Label. Do recursion.
			if key.BitLength() == bitLength {
				// Key to insert ends exactly at this node. Add it to the
				// existing internal node as LeafNode.
				result, err = t.doInsert(ctx, n.LeafNode, bitLength, key, val, depth)
			} else if key.GetBit(bitLength) {
				// Insert recursively based on the bit value.
				result, err = t.doInsert(ctx, n.Right, bitLength, key, val, depth+1)
			} else {
				result, err = t.doInsert(ctx, n.Left, bitLength, key, val, depth+1)
			}

			if err != nil {
				return insertResult{}, err
			}

			if key.BitLength() == bitLength {
				n.LeafNode = result.newRoot
			} else if key.GetBit(bitLength) {
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
		}

		// Key mismatches the label at position cpLength. Split the edge and
		// insert new leaf.
		labelPrefix, labelSuffix := n.Label.Split(cpLength, n.LabelBitLength)
		n.Label = labelSuffix
		n.LabelBitLength = n.LabelBitLength - cpLength
		n.Clean = false
		ptr.Clean = false
		// No longer eligible for eviction as it is dirty.
		t.cache.rollbackNode(ptr)

		newLeaf := t.cache.newLeafNode(key, val)
		var leafNode, left, right *node.Pointer

		if key.BitLength()-bitDepth == cpLength {
			// The key is a prefix of existing path.
			leafNode = newLeaf
			if labelSuffix.GetBit(0) {
				left = nil
				right = ptr
			} else {
				left = ptr
				right = nil
			}
		} else if keyRemainder.GetBit(cpLength) {
			left = ptr
			right = newLeaf
		} else {
			left = newLeaf
			right = ptr
		}
		return insertResult{
			newRoot:      t.cache.newInternalNode(labelPrefix, cpLength, leafNode, left, right),
			insertedLeaf: newLeaf,
			existed:      false,
		}, nil
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

		var result insertResult
		_, leafKeyRemainder := n.Key.Split(bitDepth, n.Key.BitLength())
		cpLength := leafKeyRemainder.CommonPrefixLen(n.Key.BitLength()-bitDepth, keyRemainder, key.BitLength()-bitDepth)

		// Key mismatches the label at position cpLength. Split the edge.
		labelPrefix, _ := leafKeyRemainder.Split(cpLength, leafKeyRemainder.BitLength())
		newLeaf := t.cache.newLeafNode(key, val)
		result.insertedLeaf = newLeaf
		var leafNode, left, right *node.Pointer

		if key.BitLength()-bitDepth == cpLength {
			// Inserted key is a prefix of the label.
			leafNode = newLeaf
			if leafKeyRemainder.GetBit(cpLength) {
				left = nil
				right = ptr
			} else {
				left = ptr
				right = nil
			}
		} else if n.Key.BitLength()-bitDepth == cpLength {
			// Label is a prefix of the inserted key.
			leafNode = ptr
			if keyRemainder.GetBit(cpLength) {
				left = nil
				right = newLeaf
			} else {
				left = newLeaf
				right = nil
			}
		} else if keyRemainder.GetBit(cpLength) {
			left = ptr
			right = newLeaf
		} else {
			left = newLeaf
			right = ptr
		}

		result.newRoot = t.cache.newInternalNode(labelPrefix, cpLength, leafNode, left, right)
		return result, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
