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
	path []node.Node

	// pending stores the state of the subtree chunking.
	//
	// It is represented as a path from the subtree, up to the latest visited node.
	// Each node on this path has accompanying visit state that captures state of
	// its preorder traversal.
	//
	// Invariant: After every operation there must be no trailing
	// nodes whose right subtree is pending/being explored. Such
	// nodes can be safely removed, since there is nothing more to
	// be done.
	//
	// Empty pending stack means entire subtree was chunked.
	pending []pathAtom
}

func newSubtree(ndb db.NodeDB, root node.Root) (*subtree, error) {
	rootPtr := node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	}

	rootT := subtree{
		ndb:  ndb,
		root: root,
	}
	// if root is empty, we should stil return non-empty state,
	// that will produce empty proof.
	if err := rootT.visitNext(&rootPtr); err != nil {
		return nil, err
	}

	return &rootT, nil
}

// visitNext marks a node that the ptr is pointing to as pending.
func (ct *subtree) visitNext(ptr *node.Pointer) error {
	if ptr == nil {
		return nil
	}

	if ptr.Hash.IsEmpty() {
		ct.pending = append(ct.pending, pathAtom{nil, visitBefore})
		return nil
	}

	nd, err := ct.ndb.GetNode(ct.root, ptr)
	if err != nil {
		return fmt.Errorf("getting node from nodedb (ptr hash: %.8s): %w", ptr.Hash, err)
	}

	ct.pending = append(ct.pending, pathAtom{nd, visitBefore})
	return nil
}

// nextChunk creates a next chunk, taking previous chunking state into account.
func (ct *subtree) nextChunk(ctx context.Context, w io.WriteCloser, chunkSize uint64) (hash.Hash, error) {
	defer func() {
		w.Close()
		ct.trim()
	}()

	pb := syncer.NewProofBuilderV0(ct.root.Hash, ct.root.Hash)
	for _, nd := range ct.path {
		pb.Include(nd)
	}
	for _, pa := range ct.pending {
		pb.Include(pa.nd)
	}

	var lastIsLeaf bool
	for len(ct.pending) > 0 {
		select {
		case <-ctx.Done():
			return hash.Hash{}, ctx.Err()
		default:
		}

		if pb.Size() >= chunkSize && lastIsLeaf {
			break
		}

		last := ct.pending[len(ct.pending)-1]
		ct.pending = ct.pending[:len(ct.pending)-1]

		switch nd := last.nd.(type) {
		case nil:
			continue
		case *node.LeafNode:
			pb.Include(nd)
			lastIsLeaf = true
		case *node.InternalNode:
			switch last.visitState {
			case visitBefore:
				pb.Include(nd)
				lastIsLeaf = nd.LeafNode != nil // V0 proofs include leaf nodes as part of internal node
				ct.pending = append(ct.pending, pathAtom{nd, visitAt})
			case visitAt:
				ct.pending = append(ct.pending, pathAtom{nd, visitAtLeft})
				if err := ct.visitNext(nd.Left); err != nil {
					return hash.Hash{}, err
				}
			case visitAtLeft:
				ct.pending = append(ct.pending, pathAtom{nd, visitAtRight})
				if err := ct.visitNext(nd.Right); err != nil {
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

func (ct *subtree) trim() {
	// Remove all trailing nodes whose right subtree state is pending/being explored.
	for len(ct.pending) > 0 && ct.pending[len(ct.pending)-1].visitState == visitAtRight {
		ct.pending = ct.pending[:len(ct.pending)-1]
	}
}

func (ct *subtree) isFinished() bool {
	return len(ct.pending) == 0
}

func (ct *subtree) split() ([]*subtree, error) {
	if ct.isFinished() {
		return nil, nil
	}

	subroot := ct.pending[0]
	nd, ok := subroot.nd.(*node.InternalNode)
	if !ok {
		return []*subtree{ct}, nil
	}

	var tasks []*subtree
	addTask := func(parent node.Node, child *node.Pointer) error {
		if child == nil {
			return nil
		}

		cNd, err := ct.ndb.GetNode(ct.root, child)
		if err != nil {
			return fmt.Errorf("getting node from nodedb (ptr hash: %.8s): %w", child.Hash, err)
		}

		copied := append([]node.Node(nil), ct.path...)
		task := &subtree{
			ndb:     ct.ndb,
			root:    ct.root,
			path:    append(copied, parent),
			pending: []pathAtom{{nd: cNd, visitState: visitBefore}},
		}

		tasks = append(tasks, task)
		return nil
	}
	switch subroot.visitState {
	case visitBefore, visitAt:
		if nd.Left == nil && nd.Right == nil {
			return []*subtree{ct}, nil
		}
		if err := addTask(nd, nd.Left); err != nil {
			return nil, err
		}
		if err := addTask(nd, nd.Right); err != nil {
			return nil, err
		}
	case visitAtLeft:
		if len(ct.pending) == 1 {
			return []*subtree{ct}, nil
		}
		if err := addTask(nd, nd.Right); err != nil {
			return nil, err
		}
		ct.path = append(ct.path, nd)
		ct.pending = ct.pending[1:]
		tasks = append(tasks, ct)
	case visitAtRight:
		ct.path = append(ct.path, nd)
		ct.pending = ct.pending[1:] // len must be at least two if invariant holds
		tasks = append(tasks, ct)
	default:
		return nil, fmt.Errorf("unexpected state")
	}

	return tasks, nil
}
