// Package memory implements the memory backed storage backend.
package memory

import (
	"context"
	"sync"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	memoryNodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/memory"

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

	signingKey *signature.PrivateKey
}

func (b *memoryBackend) apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*hash.Hash, error) {
	var r hash.Hash

	// Check if we already have the expected new root in our local DB.
	if urkel.HasRoot(b.nodedb, expectedNewRoot) {
		// We do, don't apply anything.
		r = expectedNewRoot
	} else {
		// We don't, apply operations.
		tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}

		for _, entry := range log {
			if len(entry.Value) == 0 {
				err = tree.Remove(ctx, entry.Key)
			} else {
				err = tree.Insert(ctx, entry.Key, entry.Value)
			}
			if err != nil {
				return nil, err
			}
		}

		_, r, err = tree.Commit(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &r, nil
}

func (b *memoryBackend) signReceipt(ctx context.Context, roots []hash.Hash) (*api.Receipt, error) {
	if b.signingKey == nil {
		return nil, api.ErrCantProve
	}
	receipt := api.ReceiptBody{
		Version: 1,
		Roots:   roots,
	}
	signed, err := signature.SignSigned(*b.signingKey, api.ReceiptSignatureContext, &receipt)
	if err != nil {
		return nil, err
	}

	return &api.Receipt{
		Signed: *signed,
	}, nil
}

func (b *memoryBackend) ApplyBatch(ctx context.Context, ops []api.ApplyOp) ([]*api.Receipt, error) {
	var roots []hash.Hash
	for _, op := range ops {
		root, err := b.apply(ctx, op.Root, op.ExpectedNewRoot, op.WriteLog)
		if err != nil {
			return nil, err
		}
		roots = append(roots, *root)
	}

	receipt, err := b.signReceipt(ctx, roots)
	return []*api.Receipt{receipt}, err
}

func (b *memoryBackend) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) ([]*api.Receipt, error) {
	r, err := b.apply(ctx, root, expectedNewRoot, log)
	if err != nil {
		return nil, err
	}
	receipt, err := b.signReceipt(ctx, []hash.Hash{*r})
	return []*api.Receipt{receipt}, err
}

func (b *memoryBackend) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *memoryBackend) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetPath(ctx, root, key, startDepth)
}

func (b *memoryBackend) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetNode(ctx, root, id)
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
func New(signingKey *signature.PrivateKey) api.Backend {
	ndb, _ := memoryNodedb.New()

	b := &memoryBackend{
		logger:     logging.GetLogger("storage/memory"),
		signingKey: signingKey,
		nodedb:     ndb,
	}

	return b
}
