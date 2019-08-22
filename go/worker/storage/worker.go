package storage

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	bolt "github.com/etcd-io/bbolt"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/workerpool"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/storage"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/registration"
	"github.com/oasislabs/ekiden/go/worker/storage/committee"
)

const (
	cfgWorkerEnabled      = "worker.storage.enabled"
	cfgWorkerFetcherCount = "worker.storage.fetcher_count"
)

var (
	workerStorageDBBucketName = []byte("worker/storage/watchers")
)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(cfgWorkerEnabled)
}

// Worker is a worker handling storage operations.
type Worker struct {
	enabled bool

	commonWorker *workerCommon.Worker
	logger       *logging.Logger

	initCh       chan struct{}
	quitCh       chan struct{}
	registration *registration.Registration

	runtimes   map[signature.MapKey]*committee.Node
	watchState *bolt.DB
	fetchPool  *workerpool.Pool

	grpcPolicy *grpc.DynamicRuntimePolicyChecker
}

// New constructs a new storage worker.
func New(
	commonWorker *workerCommon.Worker,
	registration *registration.Registration,
	genesis genesis.Provider,
	dataDir string,
) (*Worker, error) {

	s := &Worker{
		enabled:      viper.GetBool(cfgWorkerEnabled),
		commonWorker: commonWorker,
		logger:       logging.GetLogger("worker/storage"),
		initCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		registration: registration,
		runtimes:     make(map[signature.MapKey]*committee.Node),
	}

	if s.enabled {
		s.fetchPool = workerpool.New("storage_fetch")
		s.fetchPool.Resize(viper.GetUint(cfgWorkerFetcherCount))

		watchState, err := bolt.Open(filepath.Join(dataDir, "worker-storage-watchers.db"), 0600, nil)
		if err != nil {
			return nil, err
		}
		err = watchState.Update(func(tx *bolt.Tx) error {
			_, berr := tx.CreateBucketIfNotExists(workerStorageDBBucketName)
			return berr
		})
		if err != nil {
			return nil, err
		}
		s.watchState = watchState

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

		// Attach storage worker to gRPC server.
		s.grpcPolicy = grpc.NewDynamicRuntimePolicyChecker()
		storage.NewGRPCServer(s.commonWorker.Grpc.Server(), s.commonWorker.Storage, s.grpcPolicy)

		// Register storage worker role.
		s.registration.RegisterRole(func(n *node.Node) error {
			n.AddRoles(node.RoleStorageWorker)

			return nil
		})

		// Start storage node for every runtime.
		for _, runtimeID := range s.commonWorker.GetConfig().Runtimes {
			if err := s.registerRuntime(commonWorker.GetRuntime(runtimeID)); err != nil {
				return nil, err
			}
		}
	}

	return s, nil
}

func (s *Worker) registerRuntime(rt *workerCommon.Runtime) error {
	commonNode := rt.GetNode()
	node, err := committee.NewNode(commonNode, s.grpcPolicy, s.fetchPool, s.watchState, workerStorageDBBucketName)
	if err != nil {
		return err
	}
	commonNode.AddHooks(node)
	s.runtimes[commonNode.RuntimeID.ToMapKey()] = node
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

			if rt.Genesis.State != nil {
				var ns common.Namespace
				copy(ns[:], rt.ID[:])

				_, err = s.commonWorker.Storage.Apply(ctx, ns, 0, emptyRoot, 0, rt.Genesis.StateRoot, rt.Genesis.State)
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

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgWorkerEnabled, false, "Enable storage worker")
		cmd.Flags().Uint(cfgWorkerFetcherCount, 4, "Number of concurrent storage diff fetchers")
	}
	for _, v := range []string{
		cfgWorkerEnabled,
		cfgWorkerFetcherCount,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
