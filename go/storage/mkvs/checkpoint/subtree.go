package checkpoint

import (
	"context"
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// visitState captures phase of preorder traversal for a given node.
type visitState uint8

const (
	// visitBefore means node is pending a visit.
	visitBefore visitState = iota
	// visitAt means node has been visited.
	visitAt
	// visitAtLeft means node's left subtree is pending/being explored.
	visitAtLeft
	// visitAtRight means node's right subtree is pending/being explored.
	visitAtRight
)

type pathAtom struct {
	nd         node.Node
	visitState visitState
}

// subtree is a subtree that is being chunked.
type subtree struct {
	ndb  db.NodeDB
	root node.Root

	// path is a path from root to subroot (exclusive).
	//
	// Invariant 1: path can only contain:
	//     a. already visited nodes, i.e. nodes that are members of the current or previous chunks.
	//     b. pending nodes if pending state is non-zero, which guarantees path to be persisted.
	path []node.Node

	// pending stores the state of the subtree chunking.
	//
	// It is represented as a path from the subtree, up to the latest visited node.
	// Each node on this path has accompanying visit state that captures state of
	// its preorder traversal.
	//
	// Invariant 2: Pending state must not contain fully visited nodes with all
	// descendants processed.
	//
	// Empty pending stack means entire subtree was chunked.
	pending []pathAtom
}

func newSubtree(ndb db.NodeDB, root node.Root) (*subtree, error) {
	rootPtr := node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	}

	rootSubtree := subtree{
		ndb:  ndb,
		root: root,
	}
	// If root is empty we should still return non-empty state
	// that will produce an empty proof.
	if err := rootSubtree.visitNext(&rootPtr); err != nil {
		return nil, err
	}

	return &rootSubtree, nil
}

// visitNext marks a node that the ptr is pointing to as pending.
func (s *subtree) visitNext(ptr *node.Pointer) error {
	if ptr == nil {
		return nil
	}

	if ptr.Hash.IsEmpty() {
		s.pending = append(s.pending, pathAtom{nil, visitBefore})
		return nil
	}

	nd, err := s.ndb.GetNode(s.root, ptr)
	if err != nil {
		return fmt.Errorf("getting node from nodedb (ptr hash: %.8s): %w", ptr.Hash, err)
	}

	s.pending = append(s.pending, pathAtom{nd, visitBefore})
	return nil
}

// nextChunk creates a next chunk, taking previous chunking state into account.
//
// Calling this on finished subtree produces empty chunk (proof).
func (s *subtree) nextChunk(ctx context.Context, w io.WriteCloser, chunkSize uint64) (hash.Hash, error) {
	defer func() {
		w.Close()
		s.trim()
	}()

	pb := syncer.NewProofBuilderV0(s.root.Hash, s.root.Hash)
	for _, nd := range s.path {
		pb.Include(nd)
	}
	for _, pa := range s.pending {
		pb.Include(pa.nd)
	}

	var lastIsLeaf bool
	for len(s.pending) > 0 {
		select {
		case <-ctx.Done():
			return hash.Hash{}, ctx.Err()
		default:
		}

		if pb.Size() >= chunkSize && lastIsLeaf {
			break
		}

		last := s.pending[len(s.pending)-1]
		s.pending = s.pending[:len(s.pending)-1]

		pb.Include(last.nd)

		switch nd := last.nd.(type) {
		case nil:
			continue
		case *node.LeafNode:
			lastIsLeaf = true
		case *node.InternalNode:
			switch last.visitState {
			case visitBefore:
				lastIsLeaf = false
				s.pending = append(s.pending, pathAtom{nd, visitAt})
				if nd.LeafNode != nil {
					s.pending = append(s.pending, pathAtom{nd.LeafNode.Node, visitBefore})
				}
			case visitAt:
				s.pending = append(s.pending, pathAtom{nd, visitAtLeft})
				if err := s.visitNext(nd.Left); err != nil {
					return hash.Hash{}, err
				}
			case visitAtLeft:
				s.pending = append(s.pending, pathAtom{nd, visitAtRight})
				if err := s.visitNext(nd.Right); err != nil {
					return hash.Hash{}, err
				}
			case visitAtRight:
				continue
			default:
				return hash.Hash{}, fmt.Errorf("unexpected node type")
			}
		default:
			return hash.Hash{}, fmt.Errorf("unexpected atom state")
		}
	}

	proof, err := pb.Build(ctx)
	if err != nil {
		return hash.Hash{}, err
	}

	return writeChunk(proof, w)
}

// trim removes fully visited path atoms from the pending path, thus ensuring
// the invariant 2.
func (s *subtree) trim() {
	for len(s.pending) > 0 {
		last := s.pending[len(s.pending)-1]
		switch lastNode := last.nd.(type) {
		case nil:
		case *node.LeafNode:
			return
		case *node.InternalNode:
			switch last.visitState {
			case visitBefore:
				return
			case visitAt:
				if lastNode.Left != nil || lastNode.Right != nil {
					return
				}
			case visitAtLeft:
				if lastNode.Right != nil {
					return
				}
			case visitAtRight:
			}
		}
		s.pending = s.pending[:len(s.pending)-1]
	}
}

// hasNext is true when the whole subtree has been chunked.
func (s *subtree) hasNext() bool {
	return len(s.pending) == 0
}

// split splits the subtree chunking task into 0-2 subtrees.
//
// In order to respect invariant 1 and 2 it can return:
//   - 0 subtrees if the subtree has been fully chunked already.
//   - 1 subtree if splitting is not possible and subtree has pending work.
//   - 2 subtrees ready to be chunked in parallel.
//
// It is valid to split subtree returned from this method, before processing it.
func (s *subtree) split() ([]*subtree, error) {
	if s.hasNext() {
		return nil, nil
	}

	subroot := s.pending[0]
	nd, ok := subroot.nd.(*node.InternalNode)
	if !ok {
		return []*subtree{s}, nil
	}

	var tasks []*subtree
	addTask := func(parent node.Node, child *node.Pointer) error {
		if child == nil {
			return nil
		}

		childNode, err := s.ndb.GetNode(s.root, child)
		if err != nil {
			return fmt.Errorf("getting node from nodedb (ptr hash: %.8s): %w", child.Hash, err)
		}

		copied := append([]node.Node{}, s.path...)
		task := &subtree{
			ndb:     s.ndb,
			root:    s.root,
			path:    append(copied, parent),
			pending: []pathAtom{{nd: childNode, visitState: visitBefore}},
		}

		tasks = append(tasks, task)
		return nil
	}
	switch subroot.visitState {
	case visitBefore, visitAt:
		if nd.Left == nil && nd.Right == nil { // can only happen for visit before
			return []*subtree{s}, nil // prevent breaking invariant 1
		}
		if err := addTask(nd, nd.Left); err != nil {
			return nil, err
		}
		if err := addTask(nd, nd.Right); err != nil {
			return nil, err
		}
	case visitAtLeft: // pending size must be at least one (invariant 2)
		if len(s.pending) == 1 { // prevent breaking invariant 1.b and/or returning empty subtrees
			return []*subtree{s}, nil
		}
		if err := addTask(nd, nd.Right); err != nil {
			return nil, err
		}
		s.path = append(s.path, nd)
		s.pending = s.pending[1:]
		tasks = append(tasks, s)
	case visitAtRight:
		s.path = append(s.path, nd)
		s.pending = s.pending[1:]
		tasks = append(tasks, s)
	default:
		return nil, fmt.Errorf("unexpected state")
	}

	return tasks, nil
}
