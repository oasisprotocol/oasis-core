package mkvs

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// Implements Tree.
func (t *tree) DumpLocal(ctx context.Context, w io.Writer, maxDepth node.Depth) {
	t.doDumpLocal(ctx, w, t.cache.pendingRoot, 0, maxDepth)
}

func (t *tree) doDumpLocal(ctx context.Context, w io.Writer, ptr *node.Pointer, depth, maxDepth node.Depth) {
	prefix := strings.Repeat(" ", int(depth)*2)
	if ptr == nil {
		fmt.Fprint(w, prefix+"<nil>")
		return
	}

	if maxDepth > 0 && depth > maxDepth {
		fmt.Fprint(w, prefix+"<...>")
		return
	}

	nd := ptr.Node

	switch n := nd.(type) {
	case nil:
		fmt.Fprintf(w, prefix+"<nil> [%v/%s]", ptr.Clean, ptr.Hash)
	case *node.InternalNode:
		fmt.Fprintf(w, prefix+"* [%v/%q(%d)/%s]: {\n", n.Clean, n.Label, n.LabelBitLength, n.Hash)
		// NB: depth+1 for LeafNode is purely for nicer indents. LeafNode should have the same depth as parent though.
		t.doDumpLocal(ctx, w, n.LeafNode, depth+1, maxDepth)
		fmt.Fprintln(w, ",")
		t.doDumpLocal(ctx, w, n.Left, depth+1, maxDepth)
		fmt.Fprintln(w, ",")
		t.doDumpLocal(ctx, w, n.Right, depth+1, maxDepth)
		fmt.Fprintln(w, "")
		fmt.Fprint(w, prefix+"}")
	case *node.LeafNode:
		value := n.Value

		fmt.Fprintf(w, "%s- %s -> %v [%v/%s]", prefix, n.Key, value, n.Clean, n.Hash)
	default:
		fmt.Fprintf(w, prefix+"<UNKNOWN>")
	}
}
