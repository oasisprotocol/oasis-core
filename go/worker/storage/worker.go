package storage

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/workerpool"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	storageWorkerAPI "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/committee"
)

var workerStorageDBBucketName = "worker/storage/watchers"

// Worker is a worker handling storage operations.
type Worker struct {
	enabled bool

	commonWorker *workerCommon.Worker
	registration *registration.Worker
	logger       *logging.Logger

	initCh chan struct{}
	quitCh chan struct{}

	runtimes   map[common.Namespace]*committee.Node
	watchState *persistent.ServiceStore
	fetchPool  *workerpool.Pool

	grpcPolicy *policy.DynamicRuntimePolicyChecker
}

// New constructs a new storage worker.
func New(
	grpcInternal *grpc.Server,
	commonWorker *workerCommon.Worker,
	registration *registration.Worker,
	genesis genesis.Provider,
	commonStore *persistent.CommonStore,
) (*Worker, error) {
	var enabled bool
	switch commonWorker.RuntimeRegistry.Mode() {
	case runtimeRegistry.RuntimeModeCompute, runtimeRegistry.RuntimeModeClient:
		// When configured in compute or stateful client mode, enable the storage worker.
		enabled = true
	default:
		enabled = false
	}

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

	var err error

	s.fetchPool = workerpool.New("storage_fetch")
	s.fetchPool.Resize(viper.GetUint(cfgWorkerFetcherCount))

	s.watchState, err = commonStore.GetServiceStore(workerStorageDBBucketName)
	if err != nil {
		return nil, err
	}

	// Attach storage interface to gRPC server.
	localRouter := runtimeRegistry.NewStorageRouter(
		func(ns common.Namespace) (api.Backend, error) {
			node := s.GetRuntime(ns)
			if node == nil {
				return nil, fmt.Errorf("worker/storage: runtime %s is not supported", ns)
			}
			return node.GetLocalStorage(), nil
		},
		func() {
			for _, node := range s.runtimes {
				<-node.Initialized()
			}
		},
	)
	s.grpcPolicy = policy.NewDynamicRuntimePolicyChecker(api.ServiceName, s.commonWorker.GrpcPolicyWatcher)
	api.RegisterService(s.commonWorker.Grpc.Server(), &storageService{
		w:       s,
		storage: localRouter,
	})

	var checkpointerCfg *checkpoint.CheckpointerConfig
	if !viper.GetBool(CfgWorkerCheckpointerDisabled) {
		checkpointerCfg = &checkpoint.CheckpointerConfig{
			CheckInterval: viper.GetDuration(CfgWorkerCheckpointCheckInterval),
		}
	}

	// Start storage node for every runtime.
	for _, rt := range s.commonWorker.GetRuntimes() {
		if err := s.registerRuntime(commonWorker.DataDir, rt, checkpointerCfg); err != nil {
			return nil, err
		}
	}

	// Attach the storage worker's internal GRPC interface.
	storageWorkerAPI.RegisterService(grpcInternal.Server(), s)

	return s, nil
}

func (w *Worker) registerRuntime(dataDir string, commonNode *committeeCommon.Node, checkpointerCfg *checkpoint.CheckpointerConfig) error {
	id := commonNode.Runtime.ID()
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	rp, err := w.registration.NewRuntimeRoleProvider(node.RoleComputeWorker, id)
	if err != nil {
		return fmt.Errorf("failed to create role provider: %w", err)
	}
	var rpRPC registration.RoleProvider
	if viper.GetBool(CfgWorkerPublicRPCEnabled) {
		rpRPC, err = w.registration.NewRuntimeRoleProvider(node.RoleStorageRPC, id)
		if err != nil {
			return fmt.Errorf("failed to create rpc role provider: %w", err)
		}
	}

	path, err := runtimeRegistry.EnsureRuntimeStateDir(dataDir, id)
	if err != nil {
		return err
	}

	localStorage, err := NewLocalBackend(path, id, commonNode.Identity)
	if err != nil {
		return fmt.Errorf("can't create local storage backend: %w", err)
	}

	node, err := committee.NewNode(
		commonNode,
		w.grpcPolicy,
		w.fetchPool,
		w.watchState,
		rp,
		rpRPC,
		w.commonWorker.GetConfig(),
		localStorage,
		checkpointerCfg,
		viper.GetBool(CfgWorkerCheckpointSyncDisabled),
	)
	if err != nil {
		return err
	}
	commonNode.Runtime.RegisterStorage(newSyncedLocalStorage(node, localStorage))
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
	go func() {
		w.logger.Info("starting storage sync services", "num_runtimes", len(w.runtimes))

		for _, r := range w.runtimes {
			_ = r.Start()
		}

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
	if w.watchState != nil {
		w.watchState.Close()
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
