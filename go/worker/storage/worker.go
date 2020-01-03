package storage

import (
	"context"
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/persistent"
	"github.com/oasislabs/oasis-core/go/common/workerpool"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/storage/api"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	committeeCommon "github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/registration"
	storageWorkerAPI "github.com/oasislabs/oasis-core/go/worker/storage/api"
	"github.com/oasislabs/oasis-core/go/worker/storage/committee"
)

const (
	// CfgWorkerEnabled enables the storage worker.
	CfgWorkerEnabled      = "worker.storage.enabled"
	cfgWorkerFetcherCount = "worker.storage.fetcher_count"

	// CfgWorkerDebugIgnoreApply is a debug option that makes the worker ignore
	// all apply operations.
	CfgWorkerDebugIgnoreApply = "worker.debug.storage.ignore_apply"
)

var (
	workerStorageDBBucketName = "worker/storage/watchers"

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgWorkerEnabled)
}

// Worker is a worker handling storage operations.
type Worker struct {
	enabled bool

	commonWorker       *workerCommon.Worker
	registrationWorker *registration.Worker
	logger             *logging.Logger

	initCh chan struct{}
	quitCh chan struct{}

	runtimes   map[common.Namespace]*committee.Node
	watchState *persistent.ServiceStore
	fetchPool  *workerpool.Pool

	grpcPolicy *grpc.DynamicRuntimePolicyChecker
}

// New constructs a new storage worker.
func New(
	grpcInternal *grpc.Server,
	commonWorker *workerCommon.Worker,
	registrationWorker *registration.Worker,
	genesis genesis.Provider,
	commonStore *persistent.CommonStore,
) (*Worker, error) {

	s := &Worker{
		enabled:            viper.GetBool(CfgWorkerEnabled),
		commonWorker:       commonWorker,
		registrationWorker: registrationWorker,
		logger:             logging.GetLogger("worker/storage"),
		initCh:             make(chan struct{}),
		quitCh:             make(chan struct{}),
		runtimes:           make(map[common.Namespace]*committee.Node),
	}

	if s.enabled {
		var err error

		s.fetchPool = workerpool.New("storage_fetch")
		s.fetchPool.Resize(viper.GetUint(cfgWorkerFetcherCount))

		s.watchState, err = commonStore.GetServiceStore(workerStorageDBBucketName)
		if err != nil {
			return nil, err
		}

		// Populate storage from genesis.
		s.commonWorker.Consensus.RegisterGenesisHook(func() {
			doc, err := genesis.GetGenesisDocument()
			if err != nil {
				s.logger.Error("failed to get genesis document",
					"err", err,
				)
				panic("failed to get genesis document")
			}

			if err = s.initGenesis(doc); err != nil {
				s.logger.Error("failed to initialize storage from genesis",
					"err", err,
				)
				panic("storage: failed to initialize storage from genesis")
			}
		})

		// Attach storage interface to gRPC server.
		s.grpcPolicy = grpc.NewDynamicRuntimePolicyChecker()
		api.RegisterService(s.commonWorker.Grpc.Server(), &storageService{
			w:                  s,
			storage:            s.commonWorker.RuntimeRegistry.StorageRouter(),
			debugRejectUpdates: viper.GetBool(CfgWorkerDebugIgnoreApply) && flags.DebugDontBlameOasis(),
		})

		// Register storage worker role.
		if err := s.registrationWorker.RegisterRole(node.RoleStorageWorker,
			func(n *node.Node) error { return nil }); err != nil {
			return nil, err
		}

		// Start storage node for every runtime.
		for _, rt := range s.commonWorker.GetRuntimes() {
			if err := s.registerRuntime(rt); err != nil {
				return nil, err
			}
		}

		// Attach the storage worker's internal GRPC interface.
		storageWorkerAPI.RegisterService(grpcInternal.Server(), s)
	}

	return s, nil
}

func (s *Worker) registerRuntime(commonNode *committeeCommon.Node) error {
	node, err := committee.NewNode(commonNode, s.grpcPolicy, s.fetchPool, s.watchState)
	if err != nil {
		return err
	}
	commonNode.AddHooks(node)
	s.runtimes[commonNode.Runtime.ID()] = node
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
		s.logger.Info("starting per-runtime block watchers")
		for _, r := range s.runtimes {
			_ = r.Start()
		}

		// Wait for runtimes to be initialized and the node to be registered.
		for _, r := range s.runtimes {
			<-r.Initialized()
		}

		<-s.registrationWorker.InitialRegistrationCh()

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

func (s *Worker) initGenesis(gen *genesis.Document) error {
	ctx := context.Background()

	s.logger.Info("initializing storage from genesis")

	// Iterate through all runtimes and see if any specify non-empty state. Initialize
	// storage for those runtimes.
	if gen.Registry.Runtimes != nil {
		var emptyRoot hash.Hash
		emptyRoot.Empty()

		for _, sigRt := range gen.Registry.Runtimes {
			rt, err := registry.VerifyRegisterRuntimeArgs(s.logger, sigRt, true)
			if err != nil {
				return err
			}

			regRt, err := s.commonWorker.RuntimeRegistry.GetRuntime(rt.ID)
			if err != nil {
				// Skip unsupported runtimes.
				s.logger.Warn("skipping unsupported runtime",
					"runtime_id", rt.ID,
				)
				continue
			}

			if rt.Genesis.State != nil {
				var ns common.Namespace
				copy(ns[:], rt.ID[:])

				_, err = regRt.Storage().Apply(ctx, &api.ApplyRequest{
					Namespace: ns,
					SrcRound:  0,
					SrcRoot:   emptyRoot,
					DstRound:  0,
					DstRoot:   rt.Genesis.StateRoot,
					WriteLog:  rt.Genesis.State,
				})
				if err != nil {
					return err
				}
			} else if !rt.Genesis.StateRoot.IsEmpty() {
				return fmt.Errorf("storage: runtime %s has non-empty state root and nil state", rt.ID)
			}
		}
	}

	return nil
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable storage worker")
	Flags.Uint(cfgWorkerFetcherCount, 4, "Number of concurrent storage diff fetchers")
	Flags.Bool(CfgWorkerDebugIgnoreApply, false, "Ignore Apply operations (for debugging purposes)")
	_ = Flags.MarkHidden(CfgWorkerDebugIgnoreApply)

	_ = viper.BindPFlags(Flags)
}
