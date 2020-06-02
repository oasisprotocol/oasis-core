package syncer

import (
	"context"
	"errors"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

type SubtreeMerger struct {
}

// MergeVerifiedSubtree merges a previously verified subtree with an
// existing tree.
func (m *SubtreeMerger) MergeVerifiedSubtree(
	ctx context.Context,
	dst *node.Pointer,
	subtree *node.Pointer,
	committer func(*node.Pointer) error,
) error {
	if dst == nil || subtree == nil {
		return nil
	}

	if !dst.Clean {
		// TODO: Support merging into non-clean subtrees. If a subtree
		//       is not clean, this means that the tree structure may
		//       be changed.
		return errors.New("merger: merging into non-clean subtree not yet supported")
	}

	// If the destination pointer is clean, sanity check that we are
	// merging correct nodes.
	if !dst.Hash.Equal(&subtree.Hash) {
		return fmt.Errorf("merger: hash mismatch during merge (expected: %s got: %s)",
			dst.Hash,
			subtree.Hash,
		)
	}

	// If the subtree node is nil, there is nothing more to merge.
	if subtree.Node == nil {
		return nil
	}

	// If destination node is nil, we can simply replace the whole subtree.
	if dst.Node == nil {
		dst.Node = subtree.Node
		if err := committer(dst); err != nil {
			return err
		}
		return nil
	}

	switch n := dst.Node.(type) {
	case *node.InternalNode:
		// This should be safe due to the hash sanity check above.
		sn := subtree.Node.(*node.InternalNode)

		// Proceed with merging children.
		if err := m.MergeVerifiedSubtree(ctx, n.Left, sn.Left, committer); err != nil {
			return err
		}
		if err := m.MergeVerifiedSubtree(ctx, n.Right, sn.Right, committer); err != nil {
			return err
		}
	case *node.LeafNode:
		// This should be safe due to the hash sanity check above.
		_ = subtree.Node.(*node.LeafNode)

		// Clean leaf nodes do not need to be touched as they are the same.
	}
	return nil
}
