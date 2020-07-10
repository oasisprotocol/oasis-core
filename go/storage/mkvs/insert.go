package mkvs

import (
	"bytes"
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// Implements Tree.
func (t *tree) Insert(ctx context.Context, key, value []byte) error {
	if value == nil {
		value = []byte{}
	}

	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return ErrClosed
	}

	// Remember where the path from root to target node ends (will end).
	t.cache.markPosition()

	var result insertResult
	result, err := t.doInsert(ctx, t.cache.pendingRoot, 0, key, value, 0)
	if err != nil {
		return err
	}

	// Update the pending write log.
	if !t.withoutWriteLog {
		entry := t.pendingWriteLog[node.ToMapKey(key)]
		if entry == nil {
			t.pendingWriteLog[node.ToMapKey(key)] = &pendingEntry{
				key:          key,
				value:        value,
				existed:      result.existed,
				insertedLeaf: result.insertedLeaf,
			}
		} else {
			entry.value = value
		}
	}

	t.cache.setPendingRoot(result.newRoot)
	return nil
}

type insertResult struct {
	newRoot      *node.Pointer
	insertedLeaf *node.Pointer
	existed      bool
}

func (t *tree) doInsert(
	ctx context.Context,
	ptr *node.Pointer,
	bitDepth node.Depth,
	key node.Key,
	val []byte,
	depth node.Depth,
) (insertResult, error) {
	if ctx.Err() != nil {
		return insertResult{}, ctx.Err()
	}

	// Dereference the node, possibly making a remote request.
	nd, err := t.cache.derefNodePtr(ctx, ptr, t.newFetcherSyncGet(key, false))
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
				if n.Clean {
					// Node was clean so old node is eligible for removal.
					t.pendingRemovedNodes = append(t.pendingRemovedNodes, n.ExtractUnchecked())
				}

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

		if n.Clean {
			// Node was clean so old node is eligible for removal.
			t.pendingRemovedNodes = append(t.pendingRemovedNodes, n.ExtractUnchecked())
		}

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
			if bytes.Equal(n.Value, val) {
				return insertResult{
					newRoot:      ptr,
					insertedLeaf: ptr,
					existed:      true,
				}, nil
			}

			if n.Clean {
				// Node is dirty so old node is eligible for removal.
				t.pendingRemovedNodes = append(t.pendingRemovedNodes, n.ExtractUnchecked())
			}

			n.Value = val
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
		panic(fmt.Sprintf("mkvs: unknown node type: %+v", n))
	}
}
