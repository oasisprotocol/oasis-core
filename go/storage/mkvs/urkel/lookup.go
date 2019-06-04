package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

func (t *Tree) doGet(ctx context.Context, ptr *internal.Pointer, depth internal.DepthType, key internal.Key) ([]byte, error) {
	node, err := t.cache.derefNodePtr(ctx, internal.NodeID{Path: key, Depth: depth}, ptr, key)
	if err != nil {
		return nil, err
	}

	switch n := node.(type) {
	case nil:
		// Reached a nil node, there is nothing here.
		return nil, nil
	case *internal.InternalNode:
		// Internal node.
		// Is lookup key a prefix of longer stored keys? Look in n.LeafNode.
		if key.BitLength() == depth {
			return t.doGet(ctx, n.LeafNode, depth, key)
		}

		// Continue recursively based on a bit value.
		if key.GetBit(depth) {
			return t.doGet(ctx, n.Right, depth+1, key)
		}

		return t.doGet(ctx, n.Left, depth+1, key)
	case *internal.LeafNode:
		// Reached a leaf node, check if key matches.
		if n.Key.Equal(key) {
			return t.cache.derefValue(ctx, n.Value)
		}
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}

	return nil, nil
}
