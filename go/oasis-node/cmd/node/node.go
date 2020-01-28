// Package node implements the Oasis node.
package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/persistent"
	"github.com/oasislabs/oasis-core/go/common/service"
	consensusAPI "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint"
	tmService "github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	tendermintTestsGenesis "github.com/oasislabs/oasis-core/go/consensus/tendermint/tests/genesis"
	"github.com/oasislabs/oasis-core/go/control"
	controlAPI "github.com/oasislabs/oasis-core/go/control/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesisAPI "github.com/oasislabs/oasis-core/go/genesis/api"
	genesisFile "github.com/oasislabs/oasis-core/go/genesis/file"
	genesisTestHelpers "github.com/oasislabs/oasis-core/go/genesis/tests/helpers"
	"github.com/oasislabs/oasis-core/go/ias"
	iasAPI "github.com/oasislabs/oasis-core/go/ias/api"
	keymanagerAPI "github.com/oasislabs/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/pprof"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/tracing"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/supplementarysanity"
	registryAPI "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client"
	runtimeClientAPI "github.com/oasislabs/oasis-core/go/runtime/client/api"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/sentry"
	sentryAPI "github.com/oasislabs/oasis-core/go/sentry/api"
	stakingAPI "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/storage"
	storageAPI "github.com/oasislabs/oasis-core/go/storage/api"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	"github.com/oasislabs/oasis-core/go/worker/compute/executor"
	"github.com/oasislabs/oasis-core/go/worker/compute/merge"
	"github.com/oasislabs/oasis-core/go/worker/compute/txnscheduler"
	workerKeymanager "github.com/oasislabs/oasis-core/go/worker/keymanager"
	"github.com/oasislabs/oasis-core/go/worker/registration"
	workerSentry "github.com/oasislabs/oasis-core/go/worker/sentry"
	workerStorage "github.com/oasislabs/oasis-core/go/worker/storage"
)

var (
	_ controlAPI.Shutdownable = (*Node)(nil)

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

const exportsSubDir = "exports"

// Run runs the Oasis node.
func Run(cmd *cobra.Command, args []string) {
	cmdCommon.SetIsNodeCmd(true)

	node, err := NewNode()
	if err != nil {
		os.Exit(1)
	}
	defer node.Cleanup()

	node.Wait()
}

// Node is the Oasis node service.
//
// WARNING: This is exposed for the benefit of tests and the interface
// is not guaranteed to be stable.
type Node struct {
	svcMgr       *background.ServiceManager
	grpcInternal *grpc.Server
	svcTmnt      tmService.TendermintService
	svcTmntSeed  *tendermint.SeedService

	stopping uint32

	commonStore *persistent.CommonStore

	NodeController  controlAPI.NodeController
	DebugController controlAPI.DebugController

	Consensus consensusAPI.Backend

	Genesis    genesisAPI.Provider
	Identity   *identity.Identity
	Beacon     beacon.Backend
	Epochtime  epochtime.Backend
	Registry   registryAPI.Backend
	RootHash   roothash.Backend
	Scheduler  scheduler.Backend
	Sentry     sentryAPI.Backend
	Staking    stakingAPI.Backend
	IAS        iasAPI.Endpoint
	KeyManager keymanagerAPI.Backend

	RuntimeRegistry runtimeRegistry.Registry
	RuntimeClient   runtimeClientAPI.RuntimeClient

	CommonWorker               *workerCommon.Worker
	ExecutorWorker             *executor.Worker
	StorageWorker              *workerStorage.Worker
	TransactionSchedulerWorker *txnscheduler.Worker
	MergeWorker                *merge.Worker
	SentryWorker               *workerSentry.Worker
	P2P                        *p2p.P2P
	RegistrationWorker         *registration.Worker
	KeymanagerWorker           *workerKeymanager.Worker
}

// Cleanup cleans up after the node has terminated.
func (n *Node) Cleanup() {
	n.svcMgr.Cleanup()
	if n.commonStore != nil {
		n.commonStore.Close()
	}
}

// Stop gracefully terminates the node.
func (n *Node) Stop() {
	if !atomic.CompareAndSwapUint32(&n.stopping, 0, 1) {
		return
	}
	n.svcMgr.Stop()
}

// Wait waits for the node to gracefully terminate.  Callers MUST
// call Cleanup() after wait returns.
func (n *Node) Wait() {
	n.svcMgr.Wait()
}

func (n *Node) RequestShutdown() <-chan struct{} {
	// This returns only the registration worker's event channel,
	// otherwise the caller (usually the control grpc server) will only
	// get notified once everything is already torn down - perhaps
	// including the server.
	n.RegistrationWorker.RequestDeregistration()
	return n.RegistrationWorker.Quit()
}

func (n *Node) RegistrationStopped() {
	n.Stop()
}

func (n *Node) initBackends() error {
	var err error

	if n.Sentry, err = sentry.New(n.Consensus, n.Identity); err != nil {
		return err
	}

	if supplementarysanity.Enabled() {
		if err = supplementarysanity.New(n.svcTmnt); err != nil {
			return err
		}
	}

	// Initialize and register the internal gRPC services.
	grpcSrv := n.grpcInternal.Server()
	scheduler.RegisterService(grpcSrv, n.Scheduler)
	registryAPI.RegisterService(grpcSrv, n.Registry)
	stakingAPI.RegisterService(grpcSrv, n.Staking)
	consensusAPI.RegisterService(grpcSrv, n.Consensus)

	cmdCommon.Logger().Debug("backends initialized")

	return nil
}

func (n *Node) initWorkers(logger *logging.Logger) error {
	dataDir := cmdCommon.DataDir()

	var err error

	genesisDoc, err := n.Genesis.GetGenesisDocument()
	if err != nil {
		return err
	}

	// Initialize the P2P worker if the compute workers are enabled. Since the P2P
	// layer does not have a separate Start method and starts listening
	// immediately when created, make sure that we don't start it if it is not
	// needed.
	//
	// Currently, only executor, txn scheduler and merge workers need P2P
	// transport.
	if compute.Enabled() {
		p2pCtx, p2pSvc := service.NewContextCleanup(context.Background())
		if genesisDoc.Registry.Parameters.DebugAllowUnroutableAddresses {
			p2p.DebugForceAllowUnroutableAddresses()
		}
		n.P2P, err = p2p.New(p2pCtx, n.Identity)
		if err != nil {
			return err
		}
		n.svcMgr.RegisterCleanupOnly(p2pSvc, "worker p2p")
	}

	// Initialize the common worker.
	n.CommonWorker, err = workerCommon.New(
		dataDir,
		compute.Enabled() || workerStorage.Enabled() || workerKeymanager.Enabled(),
		n.Identity,
		n.RootHash,
		n.Registry,
		n.Scheduler,
		n.svcTmnt,
		n.P2P,
		n.IAS,
		n.KeyManager,
		n.RuntimeRegistry,
		genesisDoc,
	)
	if err != nil {
		logger.Error("failed to start common worker",
			"err", err,
		)
		return err
	}
	n.svcMgr.Register(n.CommonWorker.Grpc)
	n.svcMgr.Register(n.CommonWorker)

	workerCommonCfg := n.CommonWorker.GetConfig()

	// Initialize the registration worker.
	n.RegistrationWorker, err = registration.New(
		dataDir,
		n.Epochtime,
		n.Registry,
		n.Identity,
		n.svcTmnt,
		n.P2P,
		&workerCommonCfg,
		n.commonStore,
		n, // the delegate to be called on registration shutdown
		n.RuntimeRegistry,
	)
	if genesisDoc.Registry.Parameters.DebugAllowUnroutableAddresses {
		registration.DebugForceAllowUnroutableAddresses()
	}

	if err != nil {
		logger.Error("failed to initialize worker registration",
			"err", err,
		)
		return err
	}
	n.svcMgr.Register(n.RegistrationWorker)

	// Initialize the key manager worker.
	n.KeymanagerWorker, err = workerKeymanager.New(
		dataDir,
		n.CommonWorker,
		n.IAS,
		n.RegistrationWorker,
		n.KeyManager,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.KeymanagerWorker)

	// Initialize the storage worker.
	n.StorageWorker, err = workerStorage.New(
		n.grpcInternal,
		n.CommonWorker,
		n.RegistrationWorker,
		n.Genesis,
		n.commonStore,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.StorageWorker)

	// Initialize the merge worker.
	n.MergeWorker, err = merge.New(
		n.CommonWorker,
		n.RegistrationWorker,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.MergeWorker)

	// Initialize the executor worker.
	n.ExecutorWorker, err = executor.New(
		dataDir,
		n.CommonWorker,
		n.MergeWorker,
		n.RegistrationWorker,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.ExecutorWorker)

	// Initialize the sentry worker.
	n.SentryWorker, err = workerSentry.New(
		n.Sentry,
		n.Identity,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.SentryWorker)

	// Initialize the transaction scheduler.
	n.TransactionSchedulerWorker, err = txnscheduler.New(
		n.CommonWorker,
		n.ExecutorWorker,
		n.RegistrationWorker,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.TransactionSchedulerWorker)

	return nil
}

func (n *Node) startWorkers(logger *logging.Logger) error {
	// Start the storage worker.
	if err := n.StorageWorker.Start(); err != nil {
		return err
	}

	// Start the executor worker.
	if err := n.ExecutorWorker.Start(); err != nil {
		return err
	}

	// Start the transaction scheduler.
	if err := n.TransactionSchedulerWorker.Start(); err != nil {
		return err
	}

	// Start the merge worker.
	if err := n.MergeWorker.Start(); err != nil {
		return err
	}

	// Start the common worker.
	if err := n.CommonWorker.Start(); err != nil {
		return err
	}

	// Start the key manager worker.
	if err := n.KeymanagerWorker.Start(); err != nil {
		return err
	}

	// Start the sentry worker.
	if err := n.SentryWorker.Start(); err != nil {
		return err
	}

	// Start the worker registration service.
	if err := n.RegistrationWorker.Start(); err != nil {
		return err
	}

	// Only start the external gRPC server if any workers are enabled.
	if n.StorageWorker.Enabled() || n.TransactionSchedulerWorker.Enabled() || n.MergeWorker.Enabled() || n.KeymanagerWorker.Enabled() {
		if err := n.CommonWorker.Grpc.Start(); err != nil {
			logger.Error("failed to start external gRPC server",
				"err", err,
			)
			return err
		}
	}

	return nil
}

func (n *Node) initGenesis(testNode bool) error {
	var err error
	n.Genesis, err = genesisFile.DefaultFileProvider()
	if err != nil {
		if os.IsNotExist(err) && testNode {
			// Well, there wasn't a genesis document and we're running unit tests,
			// so use a test node one.
			if n.Genesis, err = tendermintTestsGenesis.NewTestNodeGenesisProvider(n.Identity); err != nil {
				return err
			}

			// In case of a test node, always use the test chain context.
			genesisTestHelpers.SetTestChainContext()
			return nil
		}
		return err
	}

	// Retrieve the genesis document and use it to configure the ChainID for
	// signature domain separation. We do this as early as possible.
	genesisDoc, err := n.Genesis.GetGenesisDocument()
	if err != nil {
		return err
	}
	genesisDoc.SetChainContext()

	return nil
}

func (n *Node) dumpGenesis(ctx context.Context, blockHeight int64, epoch epochtime.EpochTime) error {
	doc, err := n.svcTmnt.StateToGenesis(ctx, blockHeight)
	if err != nil {
		return fmt.Errorf("dumpGenesis: failed to get genesis: %w", err)
	}

	exportsDir := filepath.Join(cmdCommon.DataDir(), exportsSubDir)

	if err := common.Mkdir(exportsDir); err != nil {
		return fmt.Errorf("dumpGenesis: failed to create exports dir: %w", err)
	}

	filename := filepath.Join(exportsDir, fmt.Sprintf("genesis-%s-at-%d.json", doc.ChainID, doc.Height))
	if nerr := doc.WriteFileJSON(filename); nerr != nil {
		if err := common.Mkdir(exportsDir); err != nil {
			return fmt.Errorf("dumpGenesis: failed to dump write genesis %w", err)
		}
	}

	return nil
}

// NewNode initializes and launches the Oasis node service.
//
// WARNING: This will misbehave iff cmd != RootCommand().  This is exposed
// for the benefit of tests and the interface is not guaranteed to be stable.
func NewNode() (*Node, error) {
	return newNode(false)
}

// NewTestNode initializes and launches the (test) Oasis node service.
//
// The test node uses a test genesis block and should only be used in
// unit tests.
func NewTestNode() (*Node, error) {
	return newNode(true)
}

func newNode(testNode bool) (*Node, error) {
	logger := cmdCommon.Logger()

	node := &Node{
		svcMgr: background.NewServiceManager(logger),
	}

	var startOk bool
	defer func() {
		if !startOk {
			node.svcMgr.Stop()
			node.Cleanup()
		}
	}()

	if err := cmdCommon.Init(); err != nil {
		// Common stuff like logger not correcty initialized. Print to stderr
		_, _ = fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory not configured")
		return nil, errors.New("data directory not configured")
	}

	// Load configured values for all registered crash points.
	crash.LoadViperArgValues()

	var err error

	// Open the common node store.
	node.commonStore, err = persistent.NewCommonStore(dataDir)
	if err != nil {
		logger.Error("failed to open common node store",
			"err", err,
		)
		return nil, err
	}

	// Generate/Load the node identity.
	// TODO/hsm: Configure factory dynamically.
	signerFactory := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	node.Identity, err = identity.LoadOrGenerate(dataDir, signerFactory)
	if err != nil {
		logger.Error("failed to load/generate identity",
			"err", err,
		)
		return nil, err
	}

	logger.Info("loaded/generated node identity",
		"public_key", node.Identity.NodeSigner.Public(),
	)

	// Initialize the tracing client.
	tracingSvc, err := tracing.New("oasis-node")
	if err != nil {
		logger.Error("failed to initialize tracing",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.RegisterCleanupOnly(tracingSvc, "tracing")

	// Initialize the internal gRPC server.
	// Depends on global tracer.
	node.grpcInternal, err = cmdGrpc.NewServerLocal(false)
	if err != nil {
		logger.Error("failed to initialize internal gRPC server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(node.grpcInternal)

	// Initialize the metrics server.
	metrics, err := metrics.New(node.svcMgr.Ctx)
	if err != nil {
		logger.Error("failed to initialize metrics server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := pprof.New(node.svcMgr.Ctx)
	if err != nil {
		logger.Error("failed to initialize pprof server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(profiling)

	// Start the profiling server.
	if err = profiling.Start(); err != nil {
		logger.Error("failed to start pprof server",
			"err", err,
		)
		return nil, err
	}

	// Initialize the genesis provider.
	if err = node.initGenesis(testNode); err != nil {
		logger.Error("failed to initialize the genesis provider",
			"err", err,
		)
		return nil, err
	}

	if tendermint.IsSeed() {
		// Initialize Seed node.
		node.svcTmntSeed, err = tendermint.NewSeed(dataDir, node.Identity, node.Genesis)
		if err != nil {
			logger.Error("failed to initialize seed node",
				"err", err,
			)
			return nil, err
		}
		node.svcMgr.Register(node.svcTmntSeed)
	} else {
		// Initialize Tendermint service.
		node.svcTmnt, err = tendermint.New(node.svcMgr.Ctx, dataDir, node.Identity, node.Genesis)
		if err != nil {
			logger.Error("failed to initialize tendermint service",
				"err", err,
			)
			return nil, err
		}
		node.svcMgr.Register(node.svcTmnt)
		node.Consensus = node.svcTmnt
		node.Epochtime = node.Consensus.EpochTime()
		node.Beacon = node.Consensus.Beacon()
		node.KeyManager = node.Consensus.KeyManager()
		node.Registry = node.Consensus.Registry()
		node.Staking = node.Consensus.Staking()
		node.Scheduler = node.Consensus.Scheduler()
		node.RootHash = node.Consensus.RootHash()

		// Initialize node backends.
		if err = node.initBackends(); err != nil {
			logger.Error("failed to initialize backends",
				"err", err,
			)
			return nil, err
		}

		// Register dump genesis halt hook.
		node.Consensus.RegisterHaltHook(func(ctx context.Context, blockHeight int64, epoch epochtime.EpochTime) {
			logger.Info("Consensus halt hook: dumping genesis",
				"epoch", epoch,
				"block_height", blockHeight,
			)
			if err = node.dumpGenesis(ctx, blockHeight, epoch); err != nil {
				logger.Error("halt hook: failed to dump genesis",
					"err", err,
				)
				return
			}
			logger.Info("Consensus halt hook: genesis dumped",
				"epoch", epoch,
				"block_height", blockHeight,
			)
		})
	}

	// Initialize the IAS proxy client.
	// NOTE: See reason above why this needs to happen before seed node init.
	node.IAS, err = ias.New(node.Identity)
	if err != nil {
		logger.Error("failed to initialize IAS proxy client",
			"err", err,
		)
		return nil, err
	}

	if tendermint.IsSeed() {
		// Tendermint nodes in seed mode crawl the network for
		// peers. In case of incoming connections seed node will
		// share some of the peers and immediately disconnect.
		// Because of that only start Tendermint service in case
		// were operating as it would be useless running a full
		// node.
		logger.Info("starting tendermint seed node")

		// Start the tendermint service.
		if err = node.svcTmntSeed.Start(); err != nil {
			logger.Error("failed to start tendermint seed service",
				"err", err,
			)
			return nil, err
		}

		startOk = true

		return node, nil
	}

	logger.Info("starting Oasis node")

	// Initialize the node's runtime registry.
	node.RuntimeRegistry, err = runtimeRegistry.New(node.svcMgr.Ctx, cmdCommon.DataDir(), node.Consensus, node.Identity)
	if err != nil {
		return nil, err
	}
	node.svcMgr.RegisterCleanupOnly(node.RuntimeRegistry, "runtime registry")
	storageAPI.RegisterService(node.grpcInternal.Server(), node.RuntimeRegistry.StorageRouter())

	// Initialize the runtime client.
	node.RuntimeClient, err = runtimeClient.New(
		node.svcMgr.Ctx,
		cmdCommon.DataDir(),
		node.RootHash,
		node.Scheduler,
		node.Registry,
		node.svcTmnt,
		node.RuntimeRegistry,
	)
	if err != nil {
		return nil, err
	}
	node.svcMgr.RegisterCleanupOnly(node.RuntimeClient, "client service")
	runtimeClientAPI.RegisterService(node.grpcInternal.Server(), node.RuntimeClient)
	keymanagerAPI.Service.RegisterService(node.grpcInternal.Server(), node.RuntimeClient)

	// Start metric server.
	if err = metrics.Start(); err != nil {
		logger.Error("failed to start metric server",
			"err", err,
		)
		return nil, err
	}

	// Initialize workers.
	if err = node.initWorkers(logger); err != nil {
		logger.Error("failed to initialize workers",
			"err", err,
		)
		return nil, err
	}

	// Start workers.
	if err = node.startWorkers(logger); err != nil {
		logger.Error("failed to start workers",
			"err", err,
		)
		return nil, err
	}

	// Initialize and start the node controller.
	node.NodeController = control.New(node, node.Consensus)
	controlAPI.RegisterService(node.grpcInternal.Server(), node.NodeController)
	if flags.DebugDontBlameOasis() {
		// Initialize and start the debug controller if we are in debug mode.
		node.DebugController = control.NewDebug(node.Epochtime, node.Registry)
		controlAPI.RegisterDebugService(node.grpcInternal.Server(), node.DebugController)
	}

	// Start the tendermint service.
	//
	// Note: This will only start the node if it is required by
	// one of the backends.
	if err = node.svcTmnt.Start(); err != nil {
		logger.Error("failed to start tendermint service",
			"err", err,
		)
		return nil, err
	}

	// Start the internal gRPC server.
	if err = node.grpcInternal.Start(); err != nil {
		logger.Error("failed to start internal gRPC server",
			"err", err,
		)
		return nil, err
	}

	logger.Info("initialization complete: ready to serve")
	startOk = true

	return node, nil
}

// Register registers the node maintenance sub-commands and all of it's
// children.
func Register(parentCmd *cobra.Command) {
	unsafeResetCmd.Flags().AddFlagSet(flags.DryRunFlag)
	unsafeResetCmd.Flags().AddFlagSet(unsafeResetFlags)

	parentCmd.AddCommand(unsafeResetCmd)
}

func init() {
	Flags.AddFlagSet(flags.DebugTestEntityFlags)
	Flags.AddFlagSet(flags.ConsensusValidatorFlag)
	Flags.AddFlagSet(flags.GenesisFileFlags)

	// Backend initialization flags.
	for _, v := range []*flag.FlagSet{
		metrics.Flags,
		tracing.Flags,
		cmdGrpc.ServerLocalFlags,
		pprof.Flags,
		storage.Flags,
		supplementarysanity.Flags,
		tendermint.Flags,
		ias.Flags,
		workerKeymanager.Flags,
		runtimeRegistry.Flags,
		compute.Flags,
		p2p.Flags,
		registration.Flags,
		txnscheduler.Flags,
		workerCommon.Flags,
		workerStorage.Flags,
		workerSentry.Flags,
		crash.InitFlags(),
	} {
		Flags.AddFlagSet(v)
	}
}
