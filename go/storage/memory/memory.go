// Package memory implements the memory backed storage backend.
package memory

import (
	"context"
	"sync"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/storage/api"
)

// BackendName is the name of this implementation.
const BackendName = "memory"

var (
	_ api.Backend          = (*memoryBackend)(nil)
	_ api.SweepableBackend = (*memoryBackend)(nil)
)

type memoryEntry struct {
	expiration epochtime.EpochTime
}

type memoryBackend struct {
	sync.RWMutex

	logger  *logging.Logger
	store   map[api.Key]*memoryEntry
	sweeper *api.Sweeper
	nodedb  nodedb.NodeDB

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

func (b *memoryBackend) signReceipt(ctx context.Context, roots []hash.Hash) (*api.MKVSReceipt, error) {
	receipt := api.MKVSReceiptBody{
		Version: 1,
		Roots:   roots,
	}
	signed, err := signature.SignSigned(*b.signingKey, api.MKVSReceiptSignatureContext, &receipt)
	if err != nil {
		return nil, err
	}

	return &api.MKVSReceipt{
		Signed: *signed,
	}, nil
}

func (b *memoryBackend) ApplyBatch(ctx context.Context, ops []api.ApplyOp) (*api.MKVSReceipt, error) {
	var roots []hash.Hash
	for _, op := range ops {
		root, err := b.apply(ctx, op.Root, op.ExpectedNewRoot, op.WriteLog)
		if err != nil {
			return nil, err
		}
		roots = append(roots, *root)
	}

	return b.signReceipt(ctx, roots)
}

func (b *memoryBackend) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*api.MKVSReceipt, error) {
	r, err := b.apply(ctx, root, expectedNewRoot, log)
	if err != nil {
		return nil, err
	}

	return b.signReceipt(ctx, []hash.Hash{*r})
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

func (b *memoryBackend) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetValue(ctx, root, id)
}

func (b *memoryBackend) PurgeExpired(epoch epochtime.EpochTime) {
	b.Lock()
	defer b.Unlock()

	for key, ent := range b.store {
		if ent.expiration < epoch {
			b.logger.Debug("Expire",
				"key", key,
			)
			delete(b.store, key)
		}
	}
}

func (b *memoryBackend) Cleanup() {
	b.sweeper.Close()
	b.nodedb.Close()
}

func (b *memoryBackend) Initialized() <-chan struct{} {
	return b.sweeper.Initialized()
}

// New constructs a new memory backed storage Backend instance.
func New(timeSource epochtime.Backend, signingKey *signature.PrivateKey) api.Backend {
	ndb, _ := nodedb.NewMemoryNodeDB()

	b := &memoryBackend{
		logger:     logging.GetLogger("storage/memory"),
		store:      make(map[api.Key]*memoryEntry),
		signingKey: signingKey,
		nodedb:     ndb,
	}
	b.sweeper = api.NewSweeper(b, timeSource)

	return b
}
