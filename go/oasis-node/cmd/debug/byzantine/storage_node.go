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
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// CfgNumStorageFailApply configures how many apply requests the storage
	// node should fail.
	CfgNumStorageFailApply = "num_storage_fail_apply"
	// CfgNumStorageFailApplyBatch configures how many apply-batch requests
	// the storage node should fail.
	CfgNumStorageFailApplyBatch = "num_storage_fail_apply_batch"
	// CfgFailReadRequests configures if storage node should fail read requests.
	CfgFailReadRequests = "fail_read_requests"
)

var (
	_ storage.Backend = (*storageWorker)(nil)

	errByzantine = fmt.Errorf("byzantine error")

	storageFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

type storageWorker struct {
	sync.Mutex

	id      *identity.Identity
	backend storage.Backend
	initCh  chan struct{}

	numFailApply      uint64
	numFailApplyBatch uint64
	failReadRequests  bool
}

func newStorageNode(id *identity.Identity, namespace common.Namespace, datadir string) (*storageWorker, error) {
	initCh := make(chan struct{})
	defer close(initCh)

	cfg := &api.Config{
		Backend:           database.BackendNameBadgerDB,
		DB:                filepath.Join(datadir, database.DefaultFileName(database.BackendNameBadgerDB)),
		Signer:            id.NodeSigner,
		ApplyLockLRUSlots: uint64(1000),
		Namespace:         namespace,
		MaxCacheSize:      64 * 1024 * 1024,
	}
	impl, err := database.New(cfg)
	if err != nil {
		return nil, err
	}

	return &storageWorker{
		id:                id,
		backend:           impl,
		initCh:            initCh,
		numFailApply:      viper.GetUint64(CfgNumStorageFailApply),
		numFailApplyBatch: viper.GetUint64(CfgNumStorageFailApplyBatch),
		failReadRequests:  viper.GetBool(CfgFailReadRequests),
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

func (w *storageWorker) Apply(ctx context.Context, request *storage.ApplyRequest) ([]*storage.Receipt, error) {
	w.Lock()
	defer w.Unlock()

	if w.numFailApply > 0 {
		w.numFailApply--
		return nil, errByzantine
	}

	return w.backend.Apply(ctx, request)
}

func (w *storageWorker) ApplyBatch(ctx context.Context, request *storage.ApplyBatchRequest) ([]*storage.Receipt, error) {
	w.Lock()
	defer w.Unlock()

	if w.numFailApplyBatch > 0 {
		w.numFailApplyBatch--
		return nil, errByzantine
	}

	return w.backend.ApplyBatch(ctx, request)
}

func (w *storageWorker) GetDiff(ctx context.Context, request *storage.GetDiffRequest) (storage.WriteLogIterator, error) {
	if w.failReadRequests {
		return nil, errByzantine
	}

	return w.backend.GetDiff(ctx, request)
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
