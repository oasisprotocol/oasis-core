// Package leveldb implements the LevelDB backed storage backend.
package leveldb

import (
	"context"
	"sync"

	"github.com/pkg/errors"

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
			return nil, errors.Wrap(err, "storage/leveldb: failed to Apply, op")
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
		return nil, errors.Wrap(err, "storage/leveldb: failed to Apply")
	}

	receipt, err := api.SignReceipt(b.signer, ns, dstRound, []hash.Hash{*newRoot})
	return []*api.Receipt{receipt}, err
}

func (b *leveldbBackend) Merge(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	base hash.Hash,
	others []hash.Hash,
) ([]*api.Receipt, error) {
	newRoot, err := b.rootCache.Merge(ctx, ns, round, base, others)
	if err != nil {
		return nil, errors.Wrap(err, "storage/leveldb: failed to Merge")
	}

	receipt, err := api.SignReceipt(b.signer, ns, round+1, []hash.Hash{*newRoot})
	return []*api.Receipt{receipt}, err
}

func (b *leveldbBackend) MergeBatch(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	ops []api.MergeOp,
) ([]*api.Receipt, error) {
	newRoots := make([]hash.Hash, 0, len(ops))
	for _, op := range ops {
		newRoot, err := b.rootCache.Merge(ctx, ns, round, op.Base, op.Others)
		if err != nil {
			return nil, errors.Wrap(err, "storage/leveldb: failed to Merge, op")
		}
		newRoots = append(newRoots, *newRoot)
	}

	receipt, err := api.SignReceipt(b.signer, ns, round+1, newRoots)
	return []*api.Receipt{receipt}, err
}

func (b *leveldbBackend) GetSubtree(ctx context.Context, root api.Root, id api.NodeID, maxDepth api.Depth) (*api.Subtree, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *leveldbBackend) GetPath(ctx context.Context, root api.Root, id api.NodeID, key api.Key) (*api.Subtree, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.GetPath(ctx, root, id, key)
}

func (b *leveldbBackend) GetNode(ctx context.Context, root api.Root, id api.NodeID) (api.Node, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

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

func (b *leveldbBackend) Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error {
	return b.nodedb.Finalize(ctx, namespace, round, roots)
}

func (b *leveldbBackend) Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error) {
	return b.nodedb.Prune(ctx, namespace, round)
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
	applyLockLRUSlots uint64,
	insecureSkipChecks bool,
) (api.Backend, error) {
	ndb, err := levelNodedb.New(dbDir)
	if err != nil {
		ndb.Close()
		return nil, err
	}

	rootCache, err := api.NewRootCache(ndb, nil, applyLockLRUSlots, insecureSkipChecks)
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
