package urkel

import (
	"context"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

// NodeVisitor is a function that visits a given node and returns true to continue
// traversal of child nodes or false to stop.
type NodeVisitor func(context.Context, node.Node) bool

func (t *Tree) doVisit(
	ctx context.Context,
	visitor NodeVisitor,
	ptr *node.Pointer,
	bitDepth node.Depth,
	path node.Key,
) error {
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: path, BitDepth: bitDepth}, ptr, nil)
	if err != nil {
		return err
	}

	if !visitor(ctx, nd) {
		return nil
	}

	switch n := nd.(type) {
	case *node.InternalNode:
		bitLength := bitDepth + n.LabelBitLength

		err = t.doVisit(ctx, visitor, n.LeafNode, bitLength, path)
		if err != nil {
			return err
		}
		err = t.doVisit(ctx, visitor, n.Left, bitLength, path.AppendBit(bitLength, false))
		if err != nil {
			return err
		}
		err = t.doVisit(ctx, visitor, n.Right, bitLength, path.AppendBit(bitLength, true))
		if err != nil {
			return err
		}
	}
	return nil
}
