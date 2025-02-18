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
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	storageWorkerAPI "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/committee"
)

var workerStorageDBBucketName = "worker/storage/watchers"

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgWorkerEnabled)
}

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
	isArchive bool,
) (*Worker, error) {
	s := &Worker{
		enabled:      viper.GetBool(CfgWorkerEnabled),
		commonWorker: commonWorker,
		registration: registration,
		logger:       logging.GetLogger("worker/storage"),
		initCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		runtimes:     make(map[common.Namespace]*committee.Node),
	}

	if s.enabled {
		var err error

		s.fetchPool = workerpool.New("storage_fetch")
		s.fetchPool.Resize(viper.GetUint(cfgWorkerFetcherCount))

		s.watchState, err = commonStore.GetServiceStore(workerStorageDBBucketName)
		if err != nil {
			return nil, err
		}

		// Attach storage interface to gRPC server.
		s.grpcPolicy = policy.NewDynamicRuntimePolicyChecker(api.ServiceName, s.commonWorker.GrpcPolicyWatcher)
		api.RegisterService(s.commonWorker.Grpc.Server(), &storageService{
			w:                  s,
			storage:            s.commonWorker.RuntimeRegistry.StorageRouter(),
			debugRejectUpdates: viper.GetBool(CfgWorkerDebugIgnoreApply) && flags.DebugDontBlameOasis(),
		})

		var checkpointerCfg *checkpoint.CheckpointerConfig
		if !viper.GetBool(CfgWorkerCheckpointerDisabled) {
			checkpointerCfg = &checkpoint.CheckpointerConfig{
				CheckInterval: viper.GetDuration(CfgWorkerCheckpointCheckInterval),
			}
		}

		// Start storage node for every runtime.
		for _, rt := range s.commonWorker.GetRuntimes() {
			if err := s.registerRuntime(commonWorker.DataDir, rt, checkpointerCfg, isArchive); err != nil {
				return nil, err
			}
		}

		// Attach the storage worker's internal GRPC interface.
		storageWorkerAPI.RegisterService(grpcInternal.Server(), s)
	}

	return s, nil
}

func (s *Worker) registerRuntime(dataDir string, commonNode *committeeCommon.Node, checkpointerCfg *checkpoint.CheckpointerConfig, isArchive bool) error {
	id := commonNode.Runtime.ID()
	s.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	rp, err := s.registration.NewRuntimeRoleProvider(node.RoleStorageWorker, id)
	if err != nil {
		return fmt.Errorf("failed to create role provider: %w", err)
	}

	path, err := registry.EnsureRuntimeStateDir(dataDir, id)
	if err != nil {
		return err
	}

	localStorage, err := NewLocalBackend(path, id, commonNode.Identity)
	if err != nil {
		return fmt.Errorf("can't create local storage backend: %w", err)
	}
	commonNode.Runtime.RegisterStorage(localStorage)

	if isArchive {
		return nil
	}

	node, err := committee.NewNode(
		commonNode,
		s.grpcPolicy,
		s.fetchPool,
		s.watchState,
		rp,
		s.commonWorker.GetConfig(),
		localStorage,
		checkpointerCfg,
		viper.GetBool(CfgWorkerCheckpointSyncDisabled),
	)
	if err != nil {
		return err
	}
	commonNode.AddHooks(node)
	s.runtimes[id] = node

	s.logger.Info("new runtime registered",
		"runtime_id", id,
	)

	return nil
}

// Name returns the service name.
func (s *Worker) Name() string {
	return "storage worker"
}

// Enabled returns if worker is enabled.
func (s *Worker) Enabled() bool {
	return s.enabled
}

// Initialized returns a channel that will be closed when the storage worker
// is initialized and ready to service requests.
func (s *Worker) Initialized() <-chan struct{} {
	return s.initCh
}

// Start starts the storage service.
func (s *Worker) Start() error {
	if !s.enabled {
		s.logger.Info("not starting storage worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(s.initCh)

		return nil
	}

	// Wait for all runtimes to terminate.
	go func() {
		defer close(s.quitCh)

		for _, r := range s.runtimes {
			<-r.Quit()
		}
		if s.fetchPool != nil {
			<-s.fetchPool.Quit()
		}
	}()

	// Start all runtimes and wait for initialization.
	go func() {
		s.logger.Info("starting storage sync services", "num_runtimes", len(s.runtimes))

		for _, r := range s.runtimes {
			_ = r.Start()
		}

		// Wait for runtimes to be initialized and the node to be registered.
		for _, r := range s.runtimes {
			<-r.Initialized()
		}

		<-s.registration.InitialRegistrationCh()

		s.logger.Info("storage worker started")

		close(s.initCh)
	}()

	return nil
}

// Stop halts the service.
func (s *Worker) Stop() {
	if !s.enabled {
		close(s.quitCh)
		return
	}

	for _, r := range s.runtimes {
		r.Stop()
	}
	if s.fetchPool != nil {
		s.fetchPool.Stop()
	}
	if s.watchState != nil {
		s.watchState.Close()
	}
}

// Quit returns a channel that will be closed when the service terminates.
func (s *Worker) Quit() <-chan struct{} {
	return s.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (s *Worker) Cleanup() {
}

// GetRuntime returns a storage committee node for the given runtime (if available).
//
// In case the runtime with the specified id was not configured for this node it returns nil.
func (s *Worker) GetRuntime(id common.Namespace) *committee.Node {
	return s.runtimes[id]
}
