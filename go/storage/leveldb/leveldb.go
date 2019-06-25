// Package leveldb implements the LevelDB backed storage backend.
package leveldb

import (
	"context"
	"sync"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/storage/api"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	levelNodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/leveldb"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "leveldb"

	// DBFile is the default MKVS backing store filename.
	DBFile = "mkvs_storage.leveldb.db"
)

var _ api.Backend = (*leveldbBackend)(nil)

type leveldbBackend struct {
	logger *logging.Logger

	nodedb    nodedb.NodeDB
	rootCache *api.RootCache

	signingKey *signature.PrivateKey
	closeOnce  sync.Once
}

func (b *leveldbBackend) signReceipt(ctx context.Context, roots []hash.Hash) (*api.MKVSReceipt, error) {
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

func (b *leveldbBackend) ApplyBatch(ctx context.Context, ops []api.ApplyOp) (*api.MKVSReceipt, error) {
	var roots []hash.Hash
	for _, op := range ops {
		root, err := b.rootCache.Apply(ctx, op.Root, op.ExpectedNewRoot, op.WriteLog)
		if err != nil {
			return nil, err
		}
		roots = append(roots, *root)
	}

	return b.signReceipt(ctx, roots)
}

func (b *leveldbBackend) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*api.MKVSReceipt, error) {
	r, err := b.rootCache.Apply(ctx, root, expectedNewRoot, log)
	if err != nil {
		return nil, err
	}

	return b.signReceipt(ctx, []hash.Hash{*r})
}

func (b *leveldbBackend) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *leveldbBackend) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetPath(ctx, root, key, startDepth)
}

func (b *leveldbBackend) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetNode(ctx, root, id)
}

func (b *leveldbBackend) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetValue(ctx, root, id)
}

func (b *leveldbBackend) Cleanup() {
	b.closeOnce.Do(func() {
		b.nodedb.Close()
	})
}

func (b *leveldbBackend) Initialized() <-chan struct{} {
	initCh := make(chan struct{})
	close(initCh)
	return initCh
}

// New constructs a new LevelDB backed storage Backend instance, using
// the provided path for the database.
func New(dbDir string, signingKey *signature.PrivateKey, lruSizeInBytes uint64, applyLockLRUSlots uint64) (api.Backend, error) {
	ndb, err := levelNodedb.New(dbDir)
	if err != nil {
		ndb.Close()
		return nil, err
	}

	rootCache, err := api.NewRootCache(ndb, lruSizeInBytes, applyLockLRUSlots)
	if err != nil {
		ndb.Close()
		return nil, err
	}

	b := &leveldbBackend{
		logger:     logging.GetLogger("storage/leveldb"),
		nodedb:     ndb,
		rootCache:  rootCache,
		signingKey: signingKey,
	}

	return b, nil
}
