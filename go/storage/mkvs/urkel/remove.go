package urkel

import (
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

func (t *Tree) doRemove(ptr *internal.Pointer, depth uint8, key hash.Hash) (*internal.Pointer, bool, error) {
	node, err := t.cache.derefNodePtr(internal.NodeID{Path: key, Depth: depth}, ptr, &key)
	if err != nil {
		return nil, false, err
	}

	switch n := node.(type) {
	case nil:
		// Remove from nil node.
		return nil, false, nil
	case *internal.InternalNode:
		// Remove from internal node.
		var changed bool
		if getKeyBit(key, depth) {
			n.Right, changed, err = t.doRemove(n.Right, depth+1, key)
		} else {
			n.Left, changed, err = t.doRemove(n.Left, depth+1, key)
		}
		if err != nil {
			return nil, false, err
		}

		lrID := internal.NodeID{Path: key, Depth: depth + 1}
		if node, err = t.cache.derefNodePtr(lrID, n.Left, nil); err != nil {
			return nil, false, err
		}

		switch node.(type) {
		case nil:
			if node, err = t.cache.derefNodePtr(lrID, n.Right, nil); err != nil {
				return nil, false, err
			}

			switch node.(type) {
			case nil:
				// No more children, delete the internal node as well.
				t.cache.tryRemoveNode(ptr)
				return nil, true, nil
			case *internal.LeafNode:
				// Left is nil, right is leaf, merge nodes back.
				return n.Right, true, nil
			}
		case *internal.LeafNode:
			if node, err = t.cache.derefNodePtr(lrID, n.Right, nil); err != nil {
				return nil, false, err
			}

			switch node.(type) {
			case nil:
				// Right is nil, left is leaf, merge nodes back.
				return n.Left, true, nil
			}
		}

		if changed {
			n.Clean = false
			ptr.Clean = false
		}

		return ptr, changed, nil
	case *internal.LeafNode:
		// Remove from leaf node.
		if n.Key.Equal(&key) {
			t.cache.tryRemoveNode(ptr)
			return nil, true, nil
		}

		return ptr, false, nil
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}
}
