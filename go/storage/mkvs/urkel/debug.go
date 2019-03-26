package urkel

import (
	"fmt"
	"io"
	"strings"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

func (t *Tree) doDump(w io.Writer, ptr *internal.Pointer, path hash.Hash, depth uint8) {
	prefix := strings.Repeat(" ", int(depth)*2)
	node, err := t.cache.derefNodePtr(internal.NodeID{Path: path, Depth: depth}, ptr, nil)
	if err != nil {
		panic(err)
	}

	switch n := node.(type) {
	case nil:
		fmt.Fprint(w, prefix+"<nil>")
	case *internal.InternalNode:
		fmt.Fprintf(w, prefix+"* [%v/%s]: {\n", n.Clean, n.Hash.String())
		t.doDump(w, n.Left, setKeyBit(path, depth, false), depth+1)
		fmt.Fprintln(w, ",")
		t.doDump(w, n.Right, setKeyBit(path, depth, true), depth+1)
		fmt.Fprintln(w, "")
		fmt.Fprint(w, prefix+"}")
	case *internal.LeafNode:
		value, err := t.cache.derefValue(n.Value)
		if err != nil {
			value = []byte(fmt.Sprintf("<ERROR: %s>", err))
		}

		fmt.Fprintf(w, "%s- %s -> %s [%v/%s]", prefix, n.Key.String(), value, n.Clean, n.Hash.String())
	default:
		fmt.Fprintf(w, prefix+"<UNKNOWN>")
	}
}

func (t *Tree) doStats(s *Stats, ptr *internal.Pointer, path hash.Hash, depth uint8, maxDepth uint8) uint8 {
	if maxDepth > 0 && depth > maxDepth {
		return depth
	}
	if depth > s.MaxDepth {
		s.MaxDepth = depth
	}

	node, err := t.cache.derefNodePtr(internal.NodeID{Path: path, Depth: depth}, ptr, nil)
	if err != nil {
		panic(err)
	}

	switch n := node.(type) {
	case nil:
		s.DeadNodeCount++
	case *internal.InternalNode:
		s.InternalNodeCount++

		leftDepth := t.doStats(s, n.Left, setKeyBit(path, depth, false), depth+1, maxDepth)
		if leftDepth-depth > s.LeftSubtreeMaxDepths[depth] {
			s.LeftSubtreeMaxDepths[depth] = leftDepth - depth
		}

		rightDepth := t.doStats(s, n.Right, setKeyBit(path, depth, true), depth+1, maxDepth)
		if rightDepth-depth > s.RightSubtreeMaxDepths[depth] {
			s.RightSubtreeMaxDepths[depth] = rightDepth - depth
		}

		if leftDepth > rightDepth {
			return leftDepth
		}
		return rightDepth
	case *internal.LeafNode:
		value, err := t.cache.derefValue(n.Value)
		if err != nil {
			panic(err)
		}

		s.LeafNodeCount++
		s.LeafValueSize += uint64(len(value))
	}

	return depth
}
