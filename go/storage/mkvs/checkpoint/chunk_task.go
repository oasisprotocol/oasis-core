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

type visitState uint8

const (
	visitBefore visitState = iota
	visitAt
	visitAtLeft
	visitAfter
)

type pathAtom struct {
	nd         node.Node
	visitState visitState
}

// chunkTask is a task of creating a chunk in a given subtree,
// that may have been partially chunked already.
type chunkTask struct {
	// SubtreePath is a path from root to subroot (not included).
	//
	// A node can only be added to it if it was already chunked.
	subtreePath []node.Node
	// Pending is state of the subtree chunking.
	pending []pathAtom

	// idx is chunk index.
	idx int
	res hash.Hash
	err error
}

func rootTask(ndb db.NodeDB, root node.Root) (*chunkTask, error) {
	rootPtr := node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	}

	var task chunkTask
	// if root is empty task will have nil subroot, resulting in empty proof,
	// that is encoded as single nil node.
	task.visitNext(&rootPtr, root, ndb)
	if task.err != nil {
		return nil, task.err
	}

	return &task, nil
}

func (ct *chunkTask) visitNext(ptr *node.Pointer, root node.Root, ndb db.NodeDB) {
	if ptr == nil {
		return
	}

	if ptr.Hash.IsEmpty() {
		ct.pending = append(ct.pending, pathAtom{nil, visitBefore})
		return
	}

	nd, err := ndb.GetNode(root, ptr)
	if err != nil {
		ct.err = fmt.Errorf("getting node from nodedb (ptr hash: %.8s): %w", ptr.Hash, err)
		return
	}

	ct.pending = append(ct.pending, pathAtom{nd, visitBefore})
}

func (ct *chunkTask) process(ctx context.Context, ndb db.NodeDB, root node.Root, w io.WriteCloser, chunkSize uint64) {
	defer func() {
		w.Close()
		ct.trim()
	}()

	pb := syncer.NewProofBuilderV0(root.Hash, root.Hash)
	for _, nd := range ct.subtreePath {
		pb.Include(nd)
	}
	for _, pa := range ct.pending {
		pb.Include(pa.nd)
	}

	var lastIsLeaf bool
	for len(ct.pending) > 0 {
		select {
		case <-ctx.Done():
			ct.err = ctx.Err()
			return
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
				lastIsLeaf = nd.LeafNode != nil
				ct.pending = append(ct.pending, pathAtom{nd, visitAt})
			case visitAt:
				ct.pending = append(ct.pending, pathAtom{nd, visitAtLeft})
				if ct.visitNext(nd.Left, root, ndb); ct.err != nil {
					return
				}
			case visitAtLeft:
				ct.pending = append(ct.pending, pathAtom{nd, visitAfter})
				if ct.visitNext(nd.Right, root, ndb); ct.err != nil {
					return
				}
			case visitAfter:
				continue
			default:
				ct.err = fmt.Errorf("unexpected atom state")
				return
			}
		default:
			ct.err = fmt.Errorf("unexpected node type")
			return
		}
	}

	proof, err := pb.Build(ctx)
	if err != nil {
		ct.err = err
		return
	}

	ct.res, ct.err = writeChunk(proof, w)
}

func (ct *chunkTask) isFinished() bool {
	ct.trim()
	return len(ct.pending) == 0
}

func (ct *chunkTask) trim() {
	for len(ct.pending) > 0 && ct.pending[len(ct.pending)-1].visitState == visitAfter {
		ct.pending = ct.pending[:len(ct.pending)-1]
	}
}

func (ct *chunkTask) split(ndb db.NodeDB, root node.Root) ([]*chunkTask, error) {
	if ct.isFinished() {
		return nil, nil
	}

	subroot := ct.pending[0]
	nd, ok := subroot.nd.(*node.InternalNode)
	if !ok {
		return nil, fmt.Errorf("unexpected type")
	}

	var tasks []*chunkTask
	addTask := func(ptr *node.Pointer, parent node.Node) error {
		if ptr == nil {
			return nil
		}

		nd, err := ndb.GetNode(root, ptr)
		if err != nil {
			return err
		}

		pathCopy := append([]node.Node(nil), ct.subtreePath...)
		task := &chunkTask{
			subtreePath: append(pathCopy, parent),
			pending:     []pathAtom{{nd: nd, visitState: visitBefore}},
		}

		tasks = append(tasks, task)
		return nil
	}

	switch subroot.visitState {
	case visitBefore, visitAt:
		if nd.Left == nil && nd.Right == nil {
			return []*chunkTask{ct}, nil
		}
		if err := addTask(nd.Left, nd); err != nil {
			return nil, err
		}
		if err := addTask(nd.Right, nd); err != nil {
			return nil, err
		}
	case visitAtLeft:
		if len(ct.pending) == 1 {
			return []*chunkTask{ct}, nil
		}
		if err := addTask(nd.Right, nd); err != nil {
			return nil, err
		}
		ct.subtreePath = append(ct.subtreePath, nd)
		ct.pending = ct.pending[1:]
		tasks = append(tasks, ct)
	case visitAfter:
		if len(ct.pending) == 1 {
			return []*chunkTask{ct}, nil
		}
		ct.subtreePath = append(ct.subtreePath, nd)
		ct.pending = ct.pending[1:]
		tasks = append(tasks, ct)
	default:
		return nil, fmt.Errorf("unexpected state")
	}

	return tasks, nil
}
