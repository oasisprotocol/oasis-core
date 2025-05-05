package mkvs

import (
	"context"

	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

type subtree struct {
	tree *tree
	path []*node.Pointer
}

func (st *subtree) Iterator(ctx context.Context, pb *syncer.ProofBuilder) Iterator {
	return newSubtreeIterator(ctx, st.tree, st.path, WithProofBuilder(pb))
}

func (st *subtree) Close() {
	st.tree.Close()
}

type sbtree struct {
	root *node.Pointer
	path []*node.Pointer
}

func (s sbtree) extend(ptr *node.Pointer) sbtree {
	return sbtree{
		root: ptr,
		path: append(s.path, s.root),
	}
}

func (t *tree) Subtrees(ctx context.Context, depth int) ([]Subtree, error) {
	root := sbtree{
		root: t.cache.pendingRoot,
	}
	subtrees, err := t.subtrees(ctx, []sbtree{root}, depth)
	if err != nil {
		return nil, err
	}

	result := make([]Subtree, 0)
	for _, st := range subtrees {
		result = append(result, &subtree{
			tree: newSubtreeWithRoot(t.cache.db, t.cache.syncRoot, st.root),
			path: st.path,
		})

	}
	return result, nil
}

func (t *tree) subtrees(ctx context.Context, level []sbtree, depth int) ([]sbtree, error) {
	if depth <= 0 {
		return level, nil
	}

	var nextLevel []sbtree
	for _, sbt := range level {
		nd, err := t.cache.derefNodePtr(ctx, sbt.root, nil)
		if err != nil {
			return nil, err
		}
		switch n := nd.(type) {
		case *node.InternalNode:
			for _, ptr := range []*node.Pointer{n.LeafNode, n.Left, n.Right} {
				if ptr == nil {
					continue
				}
				nextLevel = append(nextLevel, sbt.extend(ptr))
			}
		case *node.LeafNode:
			nextLevel = append(nextLevel, sbt)
			// TODO V0 proofs include leaf nodes as part of the internal node.
			// Can we avoid subtrees of single leaf node?
		}
	}

	return t.subtrees(ctx, nextLevel, depth-1)
}

func newSubtreeWithRoot(ndb db.NodeDB, root node.Root, subtree *node.Pointer) *tree {
	t := New(nil, ndb, root.Type).(*tree)
	t.cache.setPendingRoot(subtree)
	t.cache.setSyncRoot(root)
	return t
}
