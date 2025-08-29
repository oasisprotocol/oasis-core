package storage

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/config"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	storageWorkerAPI "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/committee"
)

// Worker is a worker handling storage operations for all common worker runtimes.
type Worker struct {
	enabled bool

	commonWorker *workerCommon.Worker
	registration *registration.Worker
	logger       *logging.Logger

	initCh chan struct{}
	quitCh chan struct{}

	runtimes map[common.Namespace]*committee.Worker
}

// New constructs a new storage worker.
func New(
	grpcInternal *grpc.Server,
	commonWorker *workerCommon.Worker,
	registration *registration.Worker,
) (*Worker, error) {
	enabled := config.GlobalConfig.Mode.HasLocalStorage() && len(commonWorker.GetRuntimes()) > 0

	s := &Worker{
		enabled:      enabled,
		commonWorker: commonWorker,
		registration: registration,
		logger:       logging.GetLogger("worker/storage"),
		initCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		runtimes:     make(map[common.Namespace]*committee.Worker),
	}

	if !enabled {
		return s, nil
	}

	// Register the storage worker for every runtime.
	for id, rt := range s.commonWorker.GetRuntimes() {
		if err := s.registerRuntime(rt); err != nil {
			return nil, fmt.Errorf("failed to create storage worker for runtime %s: %w", id, err)
		}
	}

	// Attach the storage worker's internal GRPC interface.
	storageWorkerAPI.RegisterService(grpcInternal.Server(), s)

	return s, nil
}

func (w *Worker) registerRuntime(commonNode *committeeCommon.Node) error {
	id := commonNode.Runtime.ID()
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	// Since the storage node is always coupled with another role, make sure to not add any
	// particular role here. Instead this only serves to prevent registration until the storage node
	// is synced by making the role provider unavailable.
	rp, err := w.registration.NewRuntimeRoleProvider(node.RoleEmpty, id)
	if err != nil {
		return fmt.Errorf("failed to create role provider: %w", err)
	}
	var rpRPC registration.RoleProvider
	if config.GlobalConfig.Storage.PublicRPCEnabled {
		rpRPC, err = w.registration.NewRuntimeRoleProvider(node.RoleStorageRPC, id)
		if err != nil {
			return fmt.Errorf("failed to create rpc role provider: %w", err)
		}
	}

	localStorage, err := NewLocalBackend(commonNode.Runtime.DataDir(), id)
	if err != nil {
		return fmt.Errorf("can't create local storage backend: %w", err)
	}

	worker, err := committee.New(
		commonNode,
		rp,
		rpRPC,
		w.commonWorker.GetConfig(),
		localStorage,
		&committee.CheckpointSyncConfig{
			Disabled:          config.GlobalConfig.Storage.CheckpointSyncDisabled,
			ChunkFetcherCount: config.GlobalConfig.Storage.FetcherCount,
		},
	)
	if err != nil {
		return err
	}
	commonNode.Runtime.RegisterStorage(localStorage)
	commonNode.AddHooks(worker)
	w.runtimes[id] = worker

	w.logger.Info("new runtime registered",
		"runtime_id", id,
	)

	return nil
}

// Name returns the worker name.
func (w *Worker) Name() string {
	return "storage worker"
}

// Enabled returns if worker is enabled.
func (w *Worker) Enabled() bool {
	return w.enabled
}

// Initialized returns a channel that will be closed when the storage worker
// is initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// Start starts the storage service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting storage worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for all runtimes to terminate.
	go func() {
		defer close(w.quitCh)

		for _, r := range w.runtimes {
			<-r.Quit()
		}
	}()

	// Start all runtimes and wait for initialization.
	go func() {
		w.logger.Info("starting storage sync services", "num_runtimes", len(w.runtimes))

		for _, r := range w.runtimes {
			_ = r.Start()
		}

		// Wait for runtimes to be initialized.
		for _, r := range w.runtimes {
			<-r.Initialized()
		}

		w.logger.Info("storage worker started")

		close(w.initCh)
	}()

	return nil
}

// Stop halts the service.
func (w *Worker) Stop() {
	if !w.enabled {
		close(w.quitCh)
		return
	}

	for _, r := range w.runtimes {
		r.Stop()
	}
}

// Quit returns a channel that will be closed when the service terminates.
func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (w *Worker) Cleanup() {
}

// GetRuntime returns a storage committee node for the given runtime (if available).
//
// In case the runtime with the specified id was not configured for this node it returns nil.
func (w *Worker) GetRuntime(id common.Namespace) *committee.Worker {
	return w.runtimes[id]
}
