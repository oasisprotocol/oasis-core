// Package database implements a database backed storage backend.
package database

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	nodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	badgerNodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
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

	initCh chan struct{}

	readOnly bool
}

// New constructs a new database backed storage Backend instance.
func New(cfg *api.Config) (api.LocalBackend, error) {
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

	rootCache, err := api.NewRootCache(ndb)
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
		initCh:       initCh,
		readOnly:     cfg.ReadOnly,
	}, nil
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

// Implements api.LocalBackend.
func (ba *databaseBackend) Apply(ctx context.Context, request *api.ApplyRequest) error {
	if ba.readOnly {
		return fmt.Errorf("storage/database: failed to Apply: %w", api.ErrReadOnly)
	}

	oldRoot := api.Root{
		Namespace: request.Namespace,
		Version:   request.SrcRound,
		Type:      request.RootType,
		Hash:      request.SrcRoot,
	}
	expectedNewRoot := api.Root{
		Namespace: request.Namespace,
		Version:   request.DstRound,
		Type:      request.RootType,
		Hash:      request.DstRoot,
	}
	_, err := ba.rootCache.Apply(
		ctx,
		oldRoot,
		expectedNewRoot,
		request.WriteLog,
	)
	if err != nil {
		return fmt.Errorf("storage/database: failed to Apply: %w", err)
	}
	return nil
}

// Implements api.LocalBackend.
func (ba *databaseBackend) Checkpointer() checkpoint.CreateRestorer {
	return ba.checkpointer
}

// Implements api.LocalBackend.
func (ba *databaseBackend) NodeDB() nodedb.NodeDB {
	return ba.nodedb
}
