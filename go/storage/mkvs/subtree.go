package mkvs

import (
	"context"
	"fmt"

	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// Subtree is readonly, iterable view into portion of a tree (subtree),
// stored in the underyling node database.
//
// The zero value of Subtree is invalid. Use NewIterSubtrees instead.
//
// Subtree and all its methods ARE NOT safe for concurrent use.
type Subtree struct {
	tree *tree

	// subtree path
	offset       node.Key
	offsetBitLen node.Depth
	isLeaf       bool
}

// Iterator returns new Iterator, respecting subtree boundaries.
//
// This method can be called multiple times. Returned iterator is not safe for
// concurrent use. Finally when done using it, Iterator.Close must be called to release
// resources.
func (st *Subtree) Iterator(ctx context.Context, pb *syncer.ProofBuilder) Iterator {
	i := newTreeIterator(ctx, st.tree, WithProofBuilder(pb))
	it := i.(*treeIterator)
	it.offset = st.offset
	it.offsetBitDepth = st.offsetBitLen
	it.isLeaf = st.isLeaf
	return it
}

// Close releases resources associated with this subtree. After calling this
// method the tree must not be used anymore.
func (st *Subtree) Close() {
	st.tree.Close()
}

func (st *Subtree) String() string {
	return fmt.Sprintf("offset: %s, offsetBitLen: %d, isLeaf: %t", st.offset, st.offsetBitLen, st.isLeaf)
}

// NewIterSubtrees returns subtrees for the given root at specified depth, where
// all returned subtrees share same underlying node database.
//
// The Depth parameter corresponds to number of nodes from root to subtree root.
//
// If terminal node is encountered before the specified depth it will be returned as-is.
// As a result, this method may return subtrees of varying sizes, including single leaf node subtrees.
// Passing depth=0 returns the subtree equivalent to whole root tree.
//
// Subtrees may be safely used concurrently as long as each goroutine operates on a separate subtree.
func NewIterSubtrees(ctx context.Context, ndb db.NodeDB, root node.Root, depth int) ([]Subtree, error) {
	tree := newTree(ndb, root)
	defer tree.Close()

	rootPath := []*node.Pointer{
		&node.Pointer{
			Clean: true,
			Hash:  root.Hash,
		}}
	sbtrs, err := subtrees(ctx, tree.cache, []subtreePath{rootPath}, depth)
	if err != nil {
		return nil, err
	}

	var result []Subtree
	for _, st := range sbtrs {
		if len(st) == 0 {
			continue
		}
		offset, bitLen, isLeaf := st.accessPath()
		if offset.Equal([]byte("0")) {
			fmt.Println("here")
		}
		tree := Subtree{
			tree:         newTree(ndb, root),
			offset:       offset,
			offsetBitLen: bitLen,
			isLeaf:       isLeaf,
		}
		result = append(result, tree)
	}
	return result, nil
}

func subtrees(ctx context.Context, cache *cache, sbtrs []subtreePath, depth int) ([]subtreePath, error) {
	if depth < 0 {
		return sbtrs, nil
	}

	var next []subtreePath
	for _, sbt := range sbtrs {
		nd, err := cache.derefNodePtr(ctx, sbt.subroot(), nil)
		if err != nil {
			return nil, err
		}
		if depth == 0 {
			next = append(next, sbt)
			continue
		}
		switch nd := nd.(type) {
		case *node.InternalNode:
			// TODO: For V0 proofs leaf nodes are part of internal ones, so we might skip it.
			// In fact we may consider hardcoding V0 instead of making it parametric.
			for _, ptr := range []*node.Pointer{nd.LeafNode, nd.Left, nd.Right} {
				if ptr == nil {
					continue
				}
				next = append(next, sbt.extend(ptr))
			}
		case *node.LeafNode:
			next = append(next, sbt)
		}
	}

	return subtrees(ctx, cache, next, depth-1)
}

func newTree(ndb db.NodeDB, root node.Root) *tree {
	new := NewWithRoot(nil, ndb, root)
	newtr := new.(*tree)
	return newtr
}

type subtreePath []*node.Pointer

func (sp subtreePath) extend(ptr *node.Pointer) subtreePath {
	copied := make([]*node.Pointer, len(sp))
	copy(copied, sp)
	return append(copied, ptr)
}

func (sp subtreePath) subroot() *node.Pointer {
	return sp[len(sp)-1]
}

func (sp subtreePath) accessPath() (node.Key, node.Depth, bool) {
	var (
		offset          node.Key
		offsetBitLength node.Depth
		isLeaf          bool // TODO  ideally remove this.
	)
	for _, n := range sp {
		switch n := n.Node.(type) {
		case *node.InternalNode:
			offset = offset.Merge(offsetBitLength, n.Label, n.LabelBitLength)
			offsetBitLength += n.LabelBitLength
		case *node.LeafNode:
			offset = n.Key
			offsetBitLength = n.Key.BitLength()
			isLeaf = true
		case nil: // TODO consider removing/enforcing no nil.
			continue
		default:
			panic("unexpected type")
		}
	}

	return offset, offsetBitLength, isLeaf
}
