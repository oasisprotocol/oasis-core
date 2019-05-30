package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

func (t *Tree) doGet(ctx context.Context, ptr *internal.Pointer, depth uint8, key hash.Hash) ([]byte, error) {
	node, err := t.cache.derefNodePtr(ctx, internal.NodeID{Path: key, Depth: depth}, ptr, &key)
	if err != nil {
		return nil, err
	}

	switch n := node.(type) {
	case nil:
		// Reached a nil node, there is nothing here.
		return nil, nil
	case *internal.InternalNode:
		// Internal node, decide based on the bit value.
		if getKeyBit(key, depth) {
			return t.doGet(ctx, n.Right, depth+1, key)
		}

		return t.doGet(ctx, n.Left, depth+1, key)
	case *internal.LeafNode:
		// Reached a leaf node, check if key matches.
		if n.Key.Equal(&key) {
			return t.cache.derefValue(ctx, n.Value)
		}
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}

	return nil, nil
}
