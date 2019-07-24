package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func (t *Tree) doGet(ctx context.Context, ptr *node.Pointer, bitDepth node.Depth, key node.Key, depth node.Depth) ([]byte, error) {
	// NB: bitDepth is the bit depth of parent of ptr, so add one bit to fetch
	// the node corresponding to key.
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, BitDepth: bitDepth + 1}, ptr, key)
	if err != nil {
		return nil, err
	}

	switch n := nd.(type) {
	case nil:
		// Reached a nil node, there is nothing here.
		return nil, nil
	case *node.InternalNode:
		// Internal node.
		bitLength := bitDepth + n.LabelBitLength

		// Does lookup key end here? Look into LeafNode.
		if key.BitLength() == bitLength {
			return t.doGet(ctx, n.LeafNode, bitLength, key, depth)
		}

		// Lookup key is too short for the current n.Label. It's not stored.
		if key.BitLength() < bitLength {
			return nil, nil
		}

		// Continue recursively based on a bit value.
		if key.GetBit(bitDepth + n.LabelBitLength) {
			return t.doGet(ctx, n.Right, bitLength, key, depth+1)
		}

		return t.doGet(ctx, n.Left, bitLength, key, depth+1)
	case *node.LeafNode:
		// Reached a leaf node, check if key matches.
		if n.Key.Equal(key) {
			return t.cache.derefValue(ctx, n.Value)
		}
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}

	return nil, nil
}
