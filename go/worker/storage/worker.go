package storage

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/workerpool"
	"github.com/oasisprotocol/oasis-core/go/config"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	storageWorkerAPI "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/committee"
)

// Worker is a worker handling storage operations.
type Worker struct {
	enabled bool

	commonWorker *workerCommon.Worker
	registration *registration.Worker
	logger       *logging.Logger

	initCh chan struct{}
	quitCh chan struct{}

	runtimes  map[common.Namespace]*committee.Node
	fetchPool *workerpool.Pool
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
		runtimes:     make(map[common.Namespace]*committee.Node),
	}

	if !enabled {
		return s, nil
	}

	s.fetchPool = workerpool.New("storage_fetch")
	s.fetchPool.Resize(config.GlobalConfig.Storage.FetcherCount)

	var checkpointerCfg *checkpoint.CheckpointerConfig
	if config.GlobalConfig.Storage.Checkpointer.Enabled {
		checkpointerCfg = &checkpoint.CheckpointerConfig{
			CheckInterval: config.GlobalConfig.Storage.Checkpointer.CheckInterval,
		}
	}

	// Start storage node for every runtime.
	for id, rt := range s.commonWorker.GetRuntimes() {
		if err := s.registerRuntime(rt, checkpointerCfg); err != nil {
			return nil, fmt.Errorf("failed to create storage worker for runtime %s: %w", id, err)
		}
	}

	// Attach the storage worker's internal GRPC interface.
	storageWorkerAPI.RegisterService(grpcInternal.Server(), s)

	return s, nil
}

func (w *Worker) registerRuntime(commonNode *committeeCommon.Node, checkpointerCfg *checkpoint.CheckpointerConfig) error {
	id := commonNode.Runtime.ID()
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	rp, err := w.registration.NewRuntimeRoleProvider(node.RoleComputeWorker, id)
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

	storageCtor := func(ctx context.Context) (storageApi.LocalBackend, error) {
		return NewLocalBackend(commonNode.Runtime.DataDir(), id)
	}

	node, err := committee.NewNode(
		commonNode,
		w.fetchPool,
		rp,
		rpRPC,
		w.commonWorker.GetConfig(),
		storageCtor,
		checkpointerCfg,
		&committee.CheckpointSyncConfig{
			Disabled:          config.GlobalConfig.Storage.CheckpointSyncDisabled,
			ChunkFetcherCount: config.GlobalConfig.Storage.FetcherCount,
		},
	)
	if err != nil {
		return err
	}
	commonNode.AddHooks(node)
	w.runtimes[id] = node

	w.logger.Info("new runtime registered",
		"runtime_id", id,
	)

	return nil
}

// Name returns the service name.
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
		if w.fetchPool != nil {
			<-w.fetchPool.Quit()
		}
	}()

	// Start all runtimes and wait for initialization.
	var err error

	w.logger.Info("starting storage sync services", "num_runtimes", len(w.runtimes))
	for id, r := range w.runtimes {
		if err = r.Start(); err != nil {
			w.logger.Error("committee node did not start successfully", "err", err, "runtime", id)
		}
		defer func(r *committee.Node) {
			if err != nil {
				r.Stop()
			}
		}(r)
	}

	go func() {
		// Wait for runtimes to be initialized and the node to be registered.
		for _, r := range w.runtimes {
			<-r.Initialized()
		}

		<-w.registration.InitialRegistrationCh()

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
	if w.fetchPool != nil {
		w.fetchPool.Stop()
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
func (w *Worker) GetRuntime(id common.Namespace) *committee.Node {
	return w.runtimes[id]
}
