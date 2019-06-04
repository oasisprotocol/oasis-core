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
func (t *Tree) GetSubtree(ctx context.Context, root hash.Hash, id internal.NodeID, maxDepth internal.DepthType) (*syncer.Subtree, error) {
	if !root.Equal(&t.cache.pendingRoot.Hash) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	// Extract the node that is at the root of the subtree.
	subtreeRoot, err := t.cache.derefNodeID(ctx, id)
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}
	path := internal.Key{}

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
	depth internal.DepthType,
	path internal.Key,
	st *syncer.Subtree,
	maxDepth internal.DepthType,
) (syncer.SubtreePointer, error) {
	// Abort in case the context is cancelled.
	select {
	case <-ctx.Done():
		return syncer.SubtreePointer{}, ctx.Err()
	default:
	}

	node, err := t.cache.derefNodePtr(ctx, internal.NodeID{Path: path, Depth: depth}, ptr, nil)
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

		// Leaf node.
		leafNodePtr, err := t.doGetSubtree(ctx, n.LeafNode, depth, path, st, maxDepth)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.LeafNode = leafNodePtr

		// To traverse subtrees resize path bit vector, if needed.
		if path.BitLength() == depth {
			var newPath = make(Key, len(path)+1)
			copy(newPath, path)
			path = newPath
		}

		// Left subtree.
		leftPtr, err := t.doGetSubtree(ctx, n.Left, depth+1, path.SetBit(depth, false), st, maxDepth)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.Left = leftPtr

		// Right subtree.
		rightPtr, err := t.doGetSubtree(ctx, n.Right, depth+1, path.SetBit(depth, true), st, maxDepth)
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
func (t *Tree) GetPath(ctx context.Context, root hash.Hash, key internal.Key, startDepth internal.DepthType) (*syncer.Subtree, error) {
	if !root.Equal(&t.cache.pendingRoot.Hash) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	subtreeRoot, err := t.cache.derefNodeID(ctx, internal.NodeID{Path: key, Depth: startDepth})
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
	depth internal.DepthType,
	key internal.Key,
	st *syncer.Subtree,
) (syncer.SubtreePointer, error) {
	// Abort in case the context is cancelled.
	select {
	case <-ctx.Done():
		return syncer.SubtreePointer{}, ctx.Err()
	default:
	}

	node, err := t.cache.derefNodePtr(ctx, internal.NodeID{Path: key, Depth: depth}, ptr, key)
	if err != nil {
		return syncer.SubtreePointer{}, err
	}
	if node == nil {
		return syncer.SubtreePointer{Index: syncer.InvalidSubtreeIndex, Valid: true}, nil
	}

	if depth < key.BitLength() && !key.GetBit(depth) {
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

		// Leaf node.
		leafNodePtr, err := t.doGetPath(ctx, n.LeafNode, depth, key, st)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.LeafNode = leafNodePtr

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

	ptr, err := t.cache.derefNodeID(ctx, id)
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}
	node, err := t.cache.derefNodePtr(ctx, id, ptr, nil)
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

	val, err := t.cache.derefValue(ctx, &internal.Value{Clean: true, Hash: id})
	if err != nil {
		return nil, syncer.ErrValueNotFound
	}

	return val, nil
}
