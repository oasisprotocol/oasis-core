package byzantine

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sync"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// CfgFailReadRequests configures whether the storage node should fail read requests.
	CfgFailReadRequests = "storage.fail_read_requests"
	// CfgCorruptGetDiff configures whether the storage node should corrupt GetDiff responses.
	CfgCorruptGetDiff = "storage.corrupt_get_diff"
)

var (
	_ storage.Backend = (*storageWorker)(nil)

	errByzantine = fmt.Errorf("byzantine error")

	storageFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

type storageWorker struct {
	sync.Mutex

	backend storage.Backend
	initCh  chan struct{}

	failReadRequests bool
	corruptGetDiff   bool
}

func newStorageNode(namespace common.Namespace, datadir string) (*storageWorker, error) {
	initCh := make(chan struct{})
	defer close(initCh)

	cfg := &storage.Config{
		Backend:      database.BackendNameBadgerDB,
		DB:           filepath.Join(datadir, database.DefaultFileName(database.BackendNameBadgerDB)),
		Namespace:    namespace,
		MaxCacheSize: 64 * 1024 * 1024,
	}
	impl, err := database.New(cfg)
	if err != nil {
		return nil, err
	}

	return &storageWorker{
		backend:          impl,
		initCh:           initCh,
		failReadRequests: viper.GetBool(CfgFailReadRequests),
		corruptGetDiff:   viper.GetBool(CfgCorruptGetDiff),
	}, nil
}

func (w *storageWorker) SyncGet(ctx context.Context, request *syncer.GetRequest) (*syncer.ProofResponse, error) {
	if w.failReadRequests {
		return nil, errByzantine
	}

	return w.backend.SyncGet(ctx, request)
}

func (w *storageWorker) SyncGetPrefixes(ctx context.Context, request *syncer.GetPrefixesRequest) (*syncer.ProofResponse, error) {
	if w.failReadRequests {
		return nil, errByzantine
	}

	return w.backend.SyncGetPrefixes(ctx, request)
}

func (w *storageWorker) SyncIterate(ctx context.Context, request *syncer.IterateRequest) (*syncer.ProofResponse, error) {
	if w.failReadRequests {
		return nil, errByzantine
	}

	return w.backend.SyncIterate(ctx, request)
}

type corruptIterator struct {
	it        storage.WriteLogIterator
	corrupted bool
}

// Implements storage.WriteLogIterator.
func (ci *corruptIterator) Next() (bool, error) {
	return ci.it.Next()
}

// Implements storage.WriteLogIterator.
func (ci *corruptIterator) Value() (storage.LogEntry, error) {
	v, err := ci.it.Value()
	if err != nil {
		return storage.LogEntry{}, err
	}

	// Corrupt the first entry.
	if !ci.corrupted {
		v.Value = []byte("corrupted")
		ci.corrupted = true
	}
	return v, nil
}

func (w *storageWorker) GetDiff(ctx context.Context, request *storage.GetDiffRequest) (storage.WriteLogIterator, error) {
	if w.failReadRequests {
		return nil, errByzantine
	}

	wl, err := w.backend.GetDiff(ctx, request)
	if err != nil {
		return nil, err
	}

	modifiedWl := wl
	if w.corruptGetDiff {
		modifiedWl = &corruptIterator{it: wl}
	}
	return modifiedWl, nil
}

func (w *storageWorker) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	if w.failReadRequests {
		return nil, errByzantine
	}

	return w.backend.GetCheckpoints(ctx, request)
}

func (w *storageWorker) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, wr io.Writer) error {
	if w.failReadRequests {
		return fmt.Errorf("failing request")
	}

	return w.backend.GetCheckpointChunk(ctx, chunk, wr)
}

func (w *storageWorker) Cleanup() {
}

func (w *storageWorker) Initialized() <-chan struct{} {
	return w.initCh
}
