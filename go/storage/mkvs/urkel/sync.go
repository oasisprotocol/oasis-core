package urkel

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

var _ syncer.ReadSyncer = (*Tree)(nil)

// GetSubtree retrieves a compressed subtree summary of the given node
// under the given root up to the specified depth.
//
// It is the responsibility of the caller to validate that the subtree
// is correct and consistent.
func (t *Tree) GetSubtree(ctx context.Context, root node.Root, id node.ID, maxDepth uint8) (*syncer.Subtree, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if !root.Equal(&t.cache.syncRoot) {
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
	ptr *node.Pointer,
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

	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: path, Depth: depth}, ptr, nil)
	if err != nil {
		return syncer.SubtreePointer{}, err
	}
	if nd == nil {
		return syncer.SubtreePointer{Index: syncer.InvalidSubtreeIndex, Valid: true}, nil
	}

	if depth >= maxDepth {
		// Nodes at maxDepth are always full nodes.
		idx, err := st.AddFullNode(nd.Extract())
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		return syncer.SubtreePointer{Index: idx, Full: true, Valid: true}, nil
	}

	switch n := nd.(type) {
	case *node.InternalNode:
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
	case *node.LeafNode:
		// All encountered leaves are always full nodes.
		idx, err := st.AddFullNode(nd.Extract())
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
func (t *Tree) GetPath(ctx context.Context, root node.Root, key hash.Hash, startDepth uint8) (*syncer.Subtree, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if !root.Equal(&t.cache.syncRoot) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	subtreeRoot, err := t.cache.derefNodeID(ctx, node.ID{Path: key, Depth: startDepth})
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}

	st := &syncer.Subtree{}
	// We can use key as path as all the bits up to startDepth must match key. We
	// could clear all of the bits after startDepth, but there is no reason to do so.
	rootPtr, err := t.doGetPath(ctx, subtreeRoot, startDepth, key, &key, st)
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
	ptr *node.Pointer,
	depth uint8,
	path hash.Hash,
	key *hash.Hash,
	st *syncer.Subtree,
) (syncer.SubtreePointer, error) {
	// Abort in case the context is cancelled.
	select {
	case <-ctx.Done():
		return syncer.SubtreePointer{}, ctx.Err()
	default:
	}

	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: path, Depth: depth}, ptr, key)
	if err != nil {
		return syncer.SubtreePointer{}, err
	}
	if nd == nil {
		return syncer.SubtreePointer{Index: syncer.InvalidSubtreeIndex, Valid: true}, nil
	}

	if key == nil {
		// Off-path nodes are always full nodes.
		idx, err := st.AddFullNode(nd.Extract())
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		return syncer.SubtreePointer{Index: idx, Full: true, Valid: true}, nil
	}

	switch n := nd.(type) {
	case *node.InternalNode:
		// Record internal node summary.
		s := syncer.InternalNodeSummary{}
		// Determine which subtree is off-path.
		var leftKey, rightKey *hash.Hash
		if getKeyBit(*key, depth) {
			// Left subtree is off-path.
			rightKey = key
		} else {
			// Right subtree is off-path.
			leftKey = key
		}

		// Left subtree.
		leftPtr, err := t.doGetPath(ctx, n.Left, depth+1, setKeyBit(path, depth, false), leftKey, st)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.Left = leftPtr

		// Right subtree.
		rightPtr, err := t.doGetPath(ctx, n.Right, depth+1, setKeyBit(path, depth, true), rightKey, st)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}
		s.Right = rightPtr

		idx, err := st.AddSummary(s)
		if err != nil {
			return syncer.SubtreePointer{}, err
		}

		return syncer.SubtreePointer{Index: idx, Full: false, Valid: true}, nil
	case *node.LeafNode:
		// All encountered leaves are always full nodes.
		idx, err := st.AddFullNode(nd.Extract())
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
func (t *Tree) GetNode(ctx context.Context, root node.Root, id node.ID) (node.Node, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if !root.Equal(&t.cache.syncRoot) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	ptr, err := t.cache.derefNodeID(ctx, id)
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}
	nd, err := t.cache.derefNodePtr(ctx, id, ptr, nil)
	if err != nil {
		return nil, syncer.ErrNodeNotFound
	}
	return nd.Extract(), nil
}
