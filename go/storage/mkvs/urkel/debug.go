package urkel

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func (t *Tree) doDump(ctx context.Context, w io.Writer, ptr *node.Pointer, path hash.Hash, depth uint8) {
	prefix := strings.Repeat(" ", int(depth)*2)
	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: path, Depth: depth}, ptr, nil)
	if err != nil {
		panic(err)
	}

	switch n := nd.(type) {
	case nil:
		fmt.Fprint(w, prefix+"<nil>")
	case *node.InternalNode:
		fmt.Fprintf(w, prefix+"* [%v/%s]: {\n", n.Clean, n.Hash.String())
		t.doDump(ctx, w, n.Left, setKeyBit(path, depth, false), depth+1)
		fmt.Fprintln(w, ",")
		t.doDump(ctx, w, n.Right, setKeyBit(path, depth, true), depth+1)
		fmt.Fprintln(w, "")
		fmt.Fprint(w, prefix+"}")
	case *node.LeafNode:
		value, err := t.cache.derefValue(ctx, n.Value)
		if err != nil {
			value = []byte(fmt.Sprintf("<ERROR: %s>", err))
		}

		fmt.Fprintf(w, "%s- %s -> %s [%v/%s]", prefix, n.Key.String(), value, n.Clean, n.Hash.String())
	default:
		fmt.Fprintf(w, prefix+"<UNKNOWN>")
	}
}

func (t *Tree) doStats(ctx context.Context, s *Stats, ptr *node.Pointer, path hash.Hash, depth uint8, maxDepth uint8) uint8 {
	if maxDepth > 0 && depth > maxDepth {
		return depth
	}
	if depth > s.MaxDepth {
		s.MaxDepth = depth
	}

	nd, err := t.cache.derefNodePtr(ctx, node.ID{Path: path, Depth: depth}, ptr, nil)
	if err != nil {
		panic(err)
	}

	switch n := nd.(type) {
	case nil:
		s.DeadNodeCount++
	case *node.InternalNode:
		s.InternalNodeCount++

		leftDepth := t.doStats(ctx, s, n.Left, setKeyBit(path, depth, false), depth+1, maxDepth)
		if leftDepth-depth > s.LeftSubtreeMaxDepths[depth] {
			s.LeftSubtreeMaxDepths[depth] = leftDepth - depth
		}

		rightDepth := t.doStats(ctx, s, n.Right, setKeyBit(path, depth, true), depth+1, maxDepth)
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
