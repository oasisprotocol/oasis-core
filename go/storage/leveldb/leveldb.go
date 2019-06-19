// Package leveldb implements the LevelDB backed storage backend.
package leveldb

import (
	"context"
	"sync"

	"github.com/oasislabs/ekiden/go/common"
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

	signer    signature.Signer
	closeOnce sync.Once
}

func (b *leveldbBackend) ApplyBatch(
	ctx context.Context,
	ns common.Namespace,
	dstRound uint64,
	ops []api.ApplyOp,
) ([]*api.Receipt, error) {
	var newRoots []hash.Hash
	for _, op := range ops {
		newRoot, err := b.rootCache.Apply(ctx, ns, op.SrcRound, op.SrcRoot, dstRound, op.DstRoot, op.WriteLog)
		if err != nil {
			return nil, err
		}
		newRoots = append(newRoots, *newRoot)
	}

	receipt, err := api.SignReceipt(b.signer, ns, dstRound, newRoots)
	return []*api.Receipt{receipt}, err
}

func (b *leveldbBackend) Apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog api.WriteLog,
) ([]*api.Receipt, error) {
	newRoot, err := b.rootCache.Apply(ctx, ns, srcRound, srcRoot, dstRound, dstRoot, writeLog)
	if err != nil {
		return nil, err
	}

	receipt, err := api.SignReceipt(b.signer, ns, dstRound, []hash.Hash{*newRoot})
	return []*api.Receipt{receipt}, err
}

func (b *leveldbBackend) GetSubtree(ctx context.Context, root api.Root, id api.NodeID, maxDepth api.Depth) (*api.Subtree, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *leveldbBackend) GetPath(ctx context.Context, root api.Root, key api.Key, startDepth api.Depth) (*api.Subtree, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetPath(ctx, root, key, startDepth)
}

func (b *leveldbBackend) GetNode(ctx context.Context, root api.Root, id api.NodeID) (api.Node, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetNode(ctx, root, id)
}

func (b *leveldbBackend) GetDiff(ctx context.Context, startRoot api.Root, endRoot api.Root) (api.WriteLogIterator, error) {
	return b.nodedb.GetWriteLog(ctx, startRoot, endRoot)
}

func (b *leveldbBackend) GetCheckpoint(ctx context.Context, root api.Root) (api.WriteLogIterator, error) {
	return b.nodedb.GetCheckpoint(ctx, root)
}

func (b *leveldbBackend) HasRoot(root api.Root) bool {
	return b.nodedb.HasRoot(root)
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
func New(
	dbDir string,
	signer signature.Signer,
	lruSizeInBytes uint64,
	applyLockLRUSlots uint64,
	insecureSkipChecks bool,
) (api.Backend, error) {
	ndb, err := levelNodedb.New(dbDir)
	if err != nil {
		ndb.Close()
		return nil, err
	}

	rootCache, err := api.NewRootCache(ndb, nil, lruSizeInBytes, applyLockLRUSlots, insecureSkipChecks)
	if err != nil {
		ndb.Close()
		return nil, err
	}

	b := &leveldbBackend{
		logger:    logging.GetLogger("storage/leveldb"),
		nodedb:    ndb,
		rootCache: rootCache,
		signer:    signer,
	}

	return b, nil
}
