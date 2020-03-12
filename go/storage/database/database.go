// Package database implements a database backed storage backend.
package database

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/checkpoint"
	nodedb "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/db/api"
	badgerNodedb "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/db/badger"
)

const (
	// BackendNameBadgerDB is the name of the BadgeDB backed database backend.
	BackendNameBadgerDB = "badger"

	// DBFileBadgerDB is the default BadgerDB backing store filename.
	DBFileBadgerDB = "mkvs_storage.badger.db"

	checkpointDir = "checkpoints"
)

// DefaultFileName returns the default database filename for the specified
// backend.
func DefaultFileName(backend string) string {
	switch backend {
	case BackendNameBadgerDB:
		return DBFileBadgerDB
	default:
		panic("storage/database: can't get default filename for unknown backend")
	}
}

type databaseBackend struct {
	nodedb       nodedb.NodeDB
	checkpointer checkpoint.CreateRestorer
	rootCache    *api.RootCache

	signer signature.Signer
	initCh chan struct{}
}

// New constructs a new database backed storage Backend instance.
func New(cfg *api.Config) (api.Backend, error) {
	ndbCfg := cfg.ToNodeDB()

	var (
		ndb nodedb.NodeDB
		err error
	)
	switch cfg.Backend {
	case BackendNameBadgerDB:
		ndb, err = badgerNodedb.New(ndbCfg)
	default:
		err = errors.New("storage/database: unsupported backend")
	}
	if err != nil {
		return nil, fmt.Errorf("storage/database: failed to create node database: %w", err)
	}

	rootCache, err := api.NewRootCache(ndb, nil, cfg.ApplyLockLRUSlots, cfg.InsecureSkipChecks)
	if err != nil {
		ndb.Close()
		return nil, fmt.Errorf("storage/database: failed to create root cache: %w", err)
	}

	// Satisfy the interface.
	initCh := make(chan struct{})
	close(initCh)

	// Create the checkpointer.
	creator, err := checkpoint.NewFileCreator(filepath.Join(cfg.DB, checkpointDir), ndb)
	if err != nil {
		ndb.Close()
		return nil, fmt.Errorf("storage/database: failed to create checkpoint creator: %w", err)
	}
	restorer, err := checkpoint.NewRestorer(ndb)
	if err != nil {
		ndb.Close()
		return nil, fmt.Errorf("storage/database: failed to create checkpoint restorer: %w", err)
	}

	return &databaseBackend{
		nodedb:       ndb,
		checkpointer: checkpoint.NewCreateRestorer(creator, restorer),
		rootCache:    rootCache,
		signer:       cfg.Signer,
		initCh:       initCh,
	}, nil
}

func (ba *databaseBackend) Apply(ctx context.Context, request *api.ApplyRequest) ([]*api.Receipt, error) {
	newRoot, err := ba.rootCache.Apply(
		ctx,
		request.Namespace,
		request.SrcRound,
		request.SrcRoot,
		request.DstRound,
		request.DstRoot,
		request.WriteLog,
	)
	if err != nil {
		return nil, fmt.Errorf("storage/database: failed to Apply: %w", err)
	}

	receipt, err := api.SignReceipt(ba.signer, request.Namespace, request.DstRound, []hash.Hash{*newRoot})
	return []*api.Receipt{receipt}, err
}

func (ba *databaseBackend) ApplyBatch(ctx context.Context, request *api.ApplyBatchRequest) ([]*api.Receipt, error) {
	newRoots := make([]hash.Hash, 0, len(request.Ops))
	for _, op := range request.Ops {
		newRoot, err := ba.rootCache.Apply(ctx, request.Namespace, op.SrcRound, op.SrcRoot, request.DstRound, op.DstRoot, op.WriteLog)
		if err != nil {
			return nil, fmt.Errorf("storage/database: failed to Apply, op: %w", err)
		}
		newRoots = append(newRoots, *newRoot)
	}

	receipt, err := api.SignReceipt(ba.signer, request.Namespace, request.DstRound, newRoots)
	return []*api.Receipt{receipt}, err
}

func (ba *databaseBackend) Merge(ctx context.Context, request *api.MergeRequest) ([]*api.Receipt, error) {
	newRoot, err := ba.rootCache.Merge(ctx, request.Namespace, request.Round, request.Base, request.Others)
	if err != nil {
		return nil, fmt.Errorf("storage/database: failed to Merge: %w", err)
	}

	receipt, err := api.SignReceipt(ba.signer, request.Namespace, request.Round+1, []hash.Hash{*newRoot})
	return []*api.Receipt{receipt}, err
}

func (ba *databaseBackend) MergeBatch(ctx context.Context, request *api.MergeBatchRequest) ([]*api.Receipt, error) {
	newRoots := make([]hash.Hash, 0, len(request.Ops))
	for _, op := range request.Ops {
		newRoot, err := ba.rootCache.Merge(ctx, request.Namespace, request.Round, op.Base, op.Others)
		if err != nil {
			return nil, fmt.Errorf("storage/database: failed to Merge, op: %w", err)
		}
		newRoots = append(newRoots, *newRoot)
	}

	receipt, err := api.SignReceipt(ba.signer, request.Namespace, request.Round+1, newRoots)
	return []*api.Receipt{receipt}, err
}

func (ba *databaseBackend) Cleanup() {
	ba.nodedb.Close()
}

func (ba *databaseBackend) Initialized() <-chan struct{} {
	return ba.initCh
}

func (ba *databaseBackend) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
	tree, err := ba.rootCache.GetTree(ctx, request.Tree.Root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.SyncGet(ctx, request)
}

func (ba *databaseBackend) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	tree, err := ba.rootCache.GetTree(ctx, request.Tree.Root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.SyncGetPrefixes(ctx, request)
}

func (ba *databaseBackend) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	tree, err := ba.rootCache.GetTree(ctx, request.Tree.Root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.SyncIterate(ctx, request)
}

func (ba *databaseBackend) GetDiff(ctx context.Context, request *api.GetDiffRequest) (api.WriteLogIterator, error) {
	return ba.nodedb.GetWriteLog(ctx, request.StartRoot, request.EndRoot)
}

func (ba *databaseBackend) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	return ba.checkpointer.GetCheckpoints(ctx, request)
}

func (ba *databaseBackend) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	return ba.checkpointer.GetCheckpointChunk(ctx, chunk, w)
}

func (ba *databaseBackend) Checkpointer() checkpoint.CreateRestorer {
	return ba.checkpointer
}

func (ba *databaseBackend) NodeDB() nodedb.NodeDB {
	return ba.nodedb
}
