package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func (t *Tree) doGet(ctx context.Context, ptr *node.Pointer, depth uint8, key hash.Hash) ([]byte, error) {
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: key, Depth: depth}, ptr, &key)
	if err != nil {
		return nil, err
	}

	switch n := nd.(type) {
	case nil:
		// Reached a nil node, there is nothing here.
		return nil, nil
	case *node.InternalNode:
		// Internal node, decide based on the bit value.
		if getKeyBit(key, depth) {
			return t.doGet(ctx, n.Right, depth+1, key)
		}

		return t.doGet(ctx, n.Left, depth+1, key)
	case *node.LeafNode:
		// Reached a leaf node, check if key matches.
		if n.Key.Equal(&key) {
			return t.cache.derefValue(ctx, n.Value)
		}
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}

	return nil, nil
}
