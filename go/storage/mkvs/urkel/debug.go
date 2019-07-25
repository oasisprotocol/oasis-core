package urkel

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func (t *Tree) doDump(ctx context.Context, w io.Writer, ptr *node.Pointer, bitDepth node.Depth, path node.Key, depth node.Depth, right bool) {
	prefix := strings.Repeat(" ", int(depth)*2)
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: path.AppendBit(bitDepth, right), BitDepth: bitDepth}, ptr, nil)
	if err != nil {
		panic(err)
	}

	switch n := nd.(type) {
	case nil:
		fmt.Fprint(w, prefix+"<nil>")
	case *node.InternalNode:
		fmt.Fprintf(w, prefix+"* [%v/%q(%d)/%s]: {\n", n.Clean, n.Label, n.LabelBitLength, n.Hash.String())
		// NB: depth+1 for LeafNode is purely for nicer indents. LeafNode should have the same depth as parent though.
		t.doDump(ctx, w, n.LeafNode, bitDepth+n.LabelBitLength, path.Merge(bitDepth, n.Label, n.LabelBitLength), depth+1, false)
		fmt.Fprintln(w, ",")
		t.doDump(ctx, w, n.Left, bitDepth+n.LabelBitLength, path.Merge(bitDepth, n.Label, n.LabelBitLength), depth+1, false)
		fmt.Fprintln(w, ",")
		t.doDump(ctx, w, n.Right, bitDepth+n.LabelBitLength, path.Merge(bitDepth, n.Label, n.LabelBitLength), depth+1, true)
		fmt.Fprintln(w, "")
		fmt.Fprint(w, prefix+"}")
	case *node.LeafNode:
		value, err := t.cache.derefValue(ctx, n.Value)
		if err != nil {
			value = []byte(fmt.Sprintf("<ERROR: %s>", err))
		}

		fmt.Fprintf(w, "%s- %s -> %s [%v/%s]", prefix, n.Key, value, n.Clean, n.Hash.String())
	default:
		fmt.Fprintf(w, prefix+"<UNKNOWN>")
	}
}

func (t *Tree) doStats(ctx context.Context, s *Stats, ptr *node.Pointer, bitDepth node.Depth, path node.Key, depth node.Depth, maxDepth node.Depth, right bool) node.Depth {
	if maxDepth > 0 && depth > maxDepth {
		return depth
	}
	if depth > s.MaxDepth {
		s.MaxDepth = depth
	}

	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: path.AppendBit(bitDepth, right), BitDepth: bitDepth}, ptr, nil)
	if err != nil {
		panic(err)
	}

	switch n := nd.(type) {
	case nil:
		s.DeadNodeCount++
	case *node.InternalNode:
		s.InternalNodeCount++

		leftDepth := t.doStats(ctx, s, n.Left, bitDepth+n.LabelBitLength, path.Merge(bitDepth, n.Label, n.LabelBitLength), depth+1, maxDepth, false)
		if leftDepth-depth > s.LeftSubtreeMaxDepths[depth] {
			s.LeftSubtreeMaxDepths[depth] = leftDepth - depth
		}

		rightDepth := t.doStats(ctx, s, n.Right, bitDepth+n.LabelBitLength, path.Merge(bitDepth, n.Label, n.LabelBitLength), depth+1, maxDepth, true)
		if rightDepth-depth > s.RightSubtreeMaxDepths[depth] {
			s.RightSubtreeMaxDepths[depth] = rightDepth - depth
		}

		if leftDepth > rightDepth {
			return leftDepth
		}
		return rightDepth
	case *node.LeafNode:
		value, err := t.cache.derefValue(ctx, n.Value)
		if err != nil {
			panic(err)
		}

		s.LeafNodeCount++
		s.LeafValueSize += uint64(len(value))
	}

	return depth
}

func (t *Tree) doDumpLocal(ctx context.Context, w io.Writer, ptr *node.Pointer, depth node.Depth, maxDepth node.Depth) {
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
