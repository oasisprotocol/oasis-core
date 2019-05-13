package urkel

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

var _ syncer.ReadSyncer = (*Tree)(nil)

// GetSubtree retrieves a compressed subtree summary of the given node
// under the given root up to the specified depth.
//
// It is the responsibility of the caller to validate that the subtree
// is correct and consistent.
func (t *Tree) GetSubtree(ctx context.Context, root hash.Hash, id internal.NodeID, maxDepth uint8) (*syncer.Subtree, error) {
	if !root.Equal(&t.cache.pendingRoot.Hash) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	// Extract the node that is at the root of the subtree.
	subtreeRoot, err := t.cache.derefNodeID(id)
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}
	path := hash.Hash{}

	st := &syncer.Subtree{}
	rootPtr, err := t.doGetSubtree(ctx, subtreeRoot, 0, path, st, maxDepth)
	if err != nil {
		return nil, errors.Wrap(err, "urkel: failed to get subtree")
	}
	st.Root = rootPtr
	if !st.Root.Valid {
		return nil, syncer.ErrInvalidRoot
	}

	return st, nil
}

func (t *Tree) doGetSubtree(
	ctx context.Context,
	ptr *internal.Pointer,
	depth uint8,
	path hash.Hash,
	st *syncer.Subtree,
	maxDepth uint8,
) (syncer.SubtreePointer, error) {
	// Abort in case the context is cancelled.
	select {
	case <-ctx.Done():
		return syncer.SubtreePointer{}, ctx.Err()
	default:
	}

	node, err := t.cache.derefNodePtr(internal.NodeID{Path: path, Depth: depth}, ptr, nil)
	if err != nil {
		return syncer.SubtreePointer{}, err
	}
	if node == nil {
		return syncer.SubtreePointer{Index: syncer.InvalidSubtreeIndex, Valid: true}, nil
	}

	if depth >= maxDepth {
		// Nodes at maxDepth are always full nodes.
		idx, err := st.AddFullNode(node.Extract())
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		return syncer.SubtreePointer{Index: idx, Full: true, Valid: true}, nil
	}

	switch n := node.(type) {
	case *internal.InternalNode:
		// Record internal node summary.
		s := syncer.InternalNodeSummary{}

		// Left subtree.
		leftPtr, err := t.doGetSubtree(ctx, n.Left, depth+1, setKeyBit(path, depth, false), st, maxDepth)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.Left = leftPtr

		// Right subtree.
		rightPtr, err := t.doGetSubtree(ctx, n.Right, depth+1, setKeyBit(path, depth, true), st, maxDepth)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.Right = rightPtr

		idx, err := st.AddSummary(s)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}

		return syncer.SubtreePointer{Index: idx, Valid: true}, nil
	case *internal.LeafNode:
		// All encountered leaves are always full nodes.
		idx, err := st.AddFullNode(node.Extract())
		if err != nil {
			return syncer.SubtreePointer{}, err
		}

		return syncer.SubtreePointer{Index: idx, Full: true, Valid: true}, nil
	default:
		panic("urkel: invalid node type")

	}
}

// GetPath retrieves a compressed path summary for the given key under
// the given root, starting at the given depth.
//
// It is the responsibility of the caller to validate that the subtree
// is correct and consistent.
func (t *Tree) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*syncer.Subtree, error) {
	if !root.Equal(&t.cache.pendingRoot.Hash) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	subtreeRoot, err := t.cache.derefNodeID(internal.NodeID{Path: key, Depth: startDepth})
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}

	st := &syncer.Subtree{}
	rootPtr, err := t.doGetPath(ctx, subtreeRoot, startDepth, key, st)
	if err != nil {
		return nil, errors.Wrap(err, "urkel: failed to get path")
	}
	st.Root = rootPtr
	if !st.Root.Valid {
		return nil, syncer.ErrInvalidRoot
	}

	return st, nil
}

func (t *Tree) doGetPath(
	ctx context.Context,
	ptr *internal.Pointer,
	depth uint8,
	key hash.Hash,
	st *syncer.Subtree,
) (syncer.SubtreePointer, error) {
	// Abort in case the context is cancelled.
	select {
	case <-ctx.Done():
		return syncer.SubtreePointer{}, ctx.Err()
	default:
	}

	node, err := t.cache.derefNodePtr(internal.NodeID{Path: key, Depth: depth}, ptr, &key)
	if err != nil {
		return syncer.SubtreePointer{}, err
	}
	if node == nil {
		return syncer.SubtreePointer{Index: syncer.InvalidSubtreeIndex, Valid: true}, nil
	}

	if !getKeyBit(key, depth) {
		// Off-path nodes are always full nodes.
		idx, err := st.AddFullNode(node.Extract())
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		return syncer.SubtreePointer{Index: idx, Full: true, Valid: true}, nil
	}

	switch n := node.(type) {
	case *internal.InternalNode:
		// Record internal node summary.
		s := syncer.InternalNodeSummary{}

		// Left subtree.
		leftPtr, err := t.doGetPath(ctx, n.Left, depth+1, key, st)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.Left = leftPtr

		// Right subtree.
		rightPtr, err := t.doGetPath(ctx, n.Right, depth+1, key, st)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.Right = rightPtr

		idx, err := st.AddSummary(s)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}

		return syncer.SubtreePointer{Index: idx, Full: false, Valid: true}, nil
	case *internal.LeafNode:
		// All encountered leaves are always full nodes.
		idx, err := st.AddFullNode(node.Extract())
		if err != nil {
			return syncer.SubtreePointer{}, err
		}

		return syncer.SubtreePointer{Index: idx, Full: true, Valid: true}, nil
	default:
		panic("urkel: invalid node type")

	}
}

// GetNode retrieves a specific node under the given root.
//
// It is the responsibility of the caller to validate that the node
// is consistent. The node's cached hash should be considered invalid
// and must be recomputed locally.
func (t *Tree) GetNode(ctx context.Context, root hash.Hash, id internal.NodeID) (internal.Node, error) {
	if !root.Equal(&t.cache.pendingRoot.Hash) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	ptr, err := t.cache.derefNodeID(id)
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}
	node, err := t.cache.derefNodePtr(id, ptr, nil)
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}
	return node.Extract(), nil
}

// GetValue retrieves a specific value under the given root.
//
// It is the responsibility of the caller to validate that the value
// is consistent.
func (t *Tree) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	if !root.Equal(&t.cache.pendingRoot.Hash) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	val, err := t.cache.derefValue(&internal.Value{Clean: true, Hash: id})
	if err != nil {
		return nil, syncer.ErrValueNotFound
	}

	return val, nil
}
