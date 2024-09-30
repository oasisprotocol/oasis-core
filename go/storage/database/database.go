// Package database implements a database backed storage backend.
package database

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db"
	dbApi "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

const (
	// BackendNameAuto is the name of the automatic backend detection "backend".
	BackendNameAuto = "auto"
	// BackendNameBadgerDB is the name of the BadgerDB backed database backend.
	BackendNameBadgerDB = "badger"
	// BackendNamePathBadger is the name of the PathBadger database backend.
	BackendNamePathBadger = "pathbadger"

	// defaultBackendName is the default backend in case automatic backend detection is enabled and
	// no previous backend exists.
	defaultBackendName = BackendNamePathBadger

	checkpointDir = "checkpoints"
)

// DefaultFileName returns the default database filename for the specified backend.
func DefaultFileName(backend string) string {
	return fmt.Sprintf("mkvs_storage.%s.db", backend)
}

type databaseBackend struct {
	ndb          dbApi.NodeDB
	checkpointer checkpoint.CreateRestorer
	rootCache    *api.RootCache

	initCh chan struct{}

	readOnly bool
}

// New constructs a new database backed storage Backend instance.
func New(cfg *api.Config) (api.LocalBackend, error) {
	if err := autoDetectBackend(cfg); err != nil {
		return nil, err
	}

	ndb, err := db.New(cfg.Backend, cfg.ToNodeDB())
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
		ndb:          ndb,
		checkpointer: checkpoint.NewCreateRestorer(creator, restorer),
		rootCache:    rootCache,
		initCh:       initCh,
		readOnly:     cfg.ReadOnly,
	}, nil
}

func (ba *databaseBackend) Cleanup() {
	ba.ndb.Close()
}

func (ba *databaseBackend) Initialized() <-chan struct{} {
	return ba.initCh
}

func (ba *databaseBackend) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
	tree, err := ba.rootCache.GetTree(request.Tree.Root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.SyncGet(ctx, request)
}

func (ba *databaseBackend) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	tree, err := ba.rootCache.GetTree(request.Tree.Root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.SyncGetPrefixes(ctx, request)
}

func (ba *databaseBackend) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	tree, err := ba.rootCache.GetTree(request.Tree.Root)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.SyncIterate(ctx, request)
}

func (ba *databaseBackend) GetDiff(ctx context.Context, request *api.GetDiffRequest) (api.WriteLogIterator, error) {
	return ba.ndb.GetWriteLog(ctx, request.StartRoot, request.EndRoot)
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
func (ba *databaseBackend) NodeDB() dbApi.NodeDB {
	return ba.ndb
}

// autoDetectBackend attempts automatic backend detection, modifying the configuration in place.
func autoDetectBackend(cfg *api.Config) error {
	if cfg.Backend != BackendNameAuto {
		return nil
	}

	// Make sure that the DefaultFileName was used to derive the subdirectory. Otherwise automatic
	// detection cannot be performed.
	if filepath.Base(cfg.DB) != DefaultFileName(cfg.Backend) {
		return fmt.Errorf("storage/database: 'auto' backend selected using a non-default path")
	}

	// Perform automatic database backend detection if selected. Detection will be based on existing
	// database directories. If multiple directories are available, the most recently modified is
	// selected.
	type foundBackend struct {
		path      string
		timestamp time.Time
		name      string
	}
	var backends []foundBackend

	for _, b := range db.Backends {
		// Generate expected filename for the given backend.
		fn := DefaultFileName(b.Name())
		maybeDb := filepath.Join(filepath.Dir(cfg.DB), fn)
		fi, err := os.Stat(maybeDb)
		if err != nil {
			continue
		}

		backends = append(backends, foundBackend{
			path:      maybeDb,
			timestamp: fi.ModTime(),
			name:      b.Name(),
		})
	}
	slices.SortFunc(backends, func(a, b foundBackend) int {
		return a.timestamp.Compare(b.timestamp)
	})

	// If no existing backends are available, use default.
	if len(backends) == 0 {
		cfg.Backend = defaultBackendName
		cfg.DB = filepath.Join(filepath.Dir(cfg.DB), DefaultFileName(cfg.Backend))
		return nil
	}

	// Otherwise, use the backend that has been updated most recently.
	b := backends[len(backends)-1]
	cfg.Backend = b.name
	cfg.DB = b.path

	return nil
}
