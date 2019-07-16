// Package memory implements the memory backed storage backend.
package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	memoryNodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/memory"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/storage/api"
)

// BackendName is the name of this implementation.
const BackendName = "memory"

var _ api.Backend = (*memoryBackend)(nil)

type memoryBackend struct {
	sync.RWMutex

	logger *logging.Logger
	nodedb nodedb.NodeDB

	signer             signature.Signer
	insecureSkipChecks bool
}

func (b *memoryBackend) apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog api.WriteLog,
) (*hash.Hash, error) {
	root := api.Root{
		Namespace: ns,
		Round:     srcRound,
		Hash:      srcRoot,
	}
	expectedNewRoot := api.Root{
		Namespace: ns,
		Round:     dstRound,
		Hash:      dstRoot,
	}

	// Sanity check the expected new root.
	if !expectedNewRoot.Follows(&root) {
		return nil, errors.New("storage/rootcache: expected root does not follow root")
	}

	var r hash.Hash

	// Check if we already have the expected new root in our local DB.
	if b.nodedb.HasRoot(expectedNewRoot) {
		// We do, don't apply anything.
		r = dstRoot
	} else {
		// We don't, apply operations.
		tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}

		for _, entry := range writeLog {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			if len(entry.Value) == 0 {
				err = tree.Remove(ctx, entry.Key)
			} else {
				err = tree.Insert(ctx, entry.Key, entry.Value)
			}
			if err != nil {
				return nil, err
			}
		}

		if !b.insecureSkipChecks {
			_, err = tree.CommitKnown(ctx, expectedNewRoot)
		} else {
			// Skip known root checks -- only for use in benchmarks.
			_, r, err = tree.Commit(ctx, ns, dstRound)
			dstRoot = r
		}
		switch err {
		case nil:
			r = dstRoot
		case urkel.ErrKnownRootMismatch:
			return nil, api.ErrExpectedRootMismatch
		default:
			return nil, err
		}
	}

	return &r, nil
}

func (b *memoryBackend) ApplyBatch(
	ctx context.Context,
	ns common.Namespace,
	dstRound uint64,
	ops []api.ApplyOp,
) ([]*api.Receipt, error) {
	var roots []hash.Hash
	for _, op := range ops {
		r, err := b.apply(ctx, ns, op.SrcRound, op.SrcRoot, dstRound, op.DstRoot, op.WriteLog)
		if err != nil {
			return nil, err
		}
		roots = append(roots, *r)
	}

	receipt, err := api.SignReceipt(b.signer, ns, dstRound, roots)
	return []*api.Receipt{receipt}, err
}

func (b *memoryBackend) Apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog api.WriteLog,
) ([]*api.Receipt, error) {
	r, err := b.apply(ctx, ns, srcRound, srcRoot, dstRound, dstRoot, writeLog)
	if err != nil {
		return nil, err
	}
	receipt, err := api.SignReceipt(b.signer, ns, dstRound, []hash.Hash{*r})
	return []*api.Receipt{receipt}, err
}

func (b *memoryBackend) GetSubtree(ctx context.Context, root api.Root, id api.NodeID, maxDepth api.Depth) (*api.Subtree, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *memoryBackend) GetPath(ctx context.Context, root api.Root, id api.NodeID, key api.Key) (*api.Subtree, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetPath(ctx, root, id, key)
}

func (b *memoryBackend) GetNode(ctx context.Context, root api.Root, id api.NodeID) (api.Node, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetNode(ctx, root, id)
}

func (b *memoryBackend) GetDiff(ctx context.Context, startRoot api.Root, endRoot api.Root) (api.WriteLogIterator, error) {
	return b.nodedb.GetWriteLog(ctx, startRoot, endRoot)
}

func (b *memoryBackend) GetCheckpoint(ctx context.Context, root api.Root) (api.WriteLogIterator, error) {
	return b.nodedb.GetCheckpoint(ctx, root)
}

func (b *memoryBackend) HasRoot(root api.Root) bool {
	return b.nodedb.HasRoot(root)
}

func (b *memoryBackend) Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error {
	return b.nodedb.Finalize(ctx, namespace, round, roots)
}

func (b *memoryBackend) Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error) {
	return b.nodedb.Prune(ctx, namespace, round)
}

func (b *memoryBackend) Cleanup() {
	b.nodedb.Close()
}

func (b *memoryBackend) Initialized() <-chan struct{} {
	initCh := make(chan struct{})
	close(initCh)
	return initCh
}

// New constructs a new memory backed storage Backend instance.
func New(signer signature.Signer, insecureSkipChecks bool) api.Backend {
	ndb, _ := memoryNodedb.New()

	b := &memoryBackend{
		logger:             logging.GetLogger("storage/memory"),
		nodedb:             ndb,
		signer:             signer,
		insecureSkipChecks: insecureSkipChecks,
	}

	return b
}
