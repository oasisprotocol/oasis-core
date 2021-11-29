// Package node implements the Oasis node.
package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/seed"
	"github.com/oasisprotocol/oasis-core/go/control"
	controlAPI "github.com/oasisprotocol/oasis-core/go/control/api"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	governanceAPI "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/ias"
	iasAPI "github.com/oasisprotocol/oasis-core/go/ias/api"
	keymanagerAPI "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/pprof"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client"
	runtimeClientAPI "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	"github.com/oasisprotocol/oasis-core/go/sentry"
	sentryAPI "github.com/oasisprotocol/oasis-core/go/sentry/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	workerBeacon "github.com/oasisprotocol/oasis-core/go/worker/beacon"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor"
	workerConsensusRPC "github.com/oasisprotocol/oasis-core/go/worker/consensusrpc"
	workerKeymanager "github.com/oasisprotocol/oasis-core/go/worker/keymanager"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	workerSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

const exportsSubDir = "exports"

// Run runs the Oasis node.
func Run(cmd *cobra.Command, args []string) {
	cmdCommon.SetIsNodeCmd(true)

	node, err := NewNode()
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled):
		// Shutdown requested during startup.
		return
	default:
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

	stopOnce sync.Once

	commonStore *persistent.CommonStore

	NodeController  controlAPI.NodeController
	DebugController controlAPI.DebugController

	Consensus consensusAPI.Backend

	Upgrader upgradeAPI.Backend
	Genesis  genesisAPI.Provider
	Identity *identity.Identity
	Sentry   sentryAPI.LocalBackend
	IAS      iasAPI.Endpoint

	RuntimeRegistry runtimeRegistry.Registry
	RuntimeClient   runtimeClientAPI.RuntimeClientService

	CommonWorker       *workerCommon.Worker
	ExecutorWorker     *executor.Worker
	StorageWorker      *workerStorage.Worker
	SentryWorker       *workerSentry.Worker
	P2P                *p2p.P2P
	RegistrationWorker *registration.Worker
	KeymanagerWorker   *workerKeymanager.Worker
	ConsensusWorker    *workerConsensusRPC.Worker
	BeaconWorker       *workerBeacon.Worker
	readyCh            chan struct{}

	logger *logging.Logger
}

// Cleanup cleans up after the node has terminated.
func (n *Node) Cleanup() {
	n.svcMgr.Cleanup()
	if n.Upgrader != nil {
		n.Upgrader.Close()
	}
	if n.commonStore != nil {
		n.commonStore.Close()
	}
}

// Stop gracefully terminates the node.
func (n *Node) Stop() {
	n.stopOnce.Do(func() {
		n.svcMgr.Stop()
	})
}

// Wait waits for the node to gracefully terminate.  Callers MUST
// call Cleanup() after wait returns.
func (n *Node) Wait() {
	n.svcMgr.Wait()
}

func (n *Node) waitReady() {
	if n.NodeController == nil {
		n.logger.Error("failed while waiting for node: node controller not initialized")
		return
	}

	if err := n.NodeController.WaitSync(context.Background()); err != nil {
		n.logger.Error("failed while waiting for node consensus sync", "err", err)
		return
	}

	// Wait for storage worker.
	if n.StorageWorker.Enabled() {
		<-n.StorageWorker.Initialized()
	}

	// Wait for executor worker (also waits runtimes to initialize).
	if n.ExecutorWorker.Enabled() {
		<-n.ExecutorWorker.Initialized()
	}

	// Wait for key manager worker.
	if n.KeymanagerWorker.Enabled() {
		<-n.KeymanagerWorker.Initialized()
	}

	// Wait for the common worker.
	if n.CommonWorker.Enabled() {
		<-n.CommonWorker.Initialized()
	}

	close(n.readyCh)
}

// startRuntimeServices initializes and starts all the services that are required for runtime
// support to work.
func (n *Node) startRuntimeServices() error {
	var err error
	if n.Sentry, err = sentry.New(n.Consensus, n.Identity); err != nil {
		return err
	}

	// Initialize and register the internal gRPC services.
	grpcSrv := n.grpcInternal.Server()
	beacon.RegisterService(grpcSrv, n.Consensus.Beacon())
	scheduler.RegisterService(grpcSrv, n.Consensus.Scheduler())
	registryAPI.RegisterService(grpcSrv, n.Consensus.Registry())
	stakingAPI.RegisterService(grpcSrv, n.Consensus.Staking())
	keymanagerAPI.RegisterService(grpcSrv, n.Consensus.KeyManager())
	roothashAPI.RegisterService(grpcSrv, n.Consensus.RootHash())
	governanceAPI.RegisterService(grpcSrv, n.Consensus.Governance())

	// Register dump genesis halt hook.
	n.Consensus.RegisterHaltHook(func(ctx context.Context, blockHeight int64, epoch beacon.EpochTime, _ error) {
		n.logger.Info("Consensus halt hook: dumping genesis",
			"epoch", epoch,
			"block_height", blockHeight+1,
		)
		if err = n.dumpGenesis(ctx, blockHeight+1, epoch); err != nil {
			n.logger.Error("halt hook: failed to dump genesis",
				"err", err,
			)
			return
		}
		n.logger.Info("Consensus halt hook: genesis dumped",
			"epoch", epoch,
			"block_height", blockHeight+1,
		)
	})

	// Initialize runtime workers.
	if err = n.initRuntimeWorkers(); err != nil {
		n.logger.Error("failed to initialize workers",
			"err", err,
		)
		return err
	}

	// Initialize the runtime client.
	n.RuntimeClient, err = runtimeClient.New(
		n.svcMgr.Ctx,
		cmdCommon.DataDir(),
		n.Consensus,
		n.RuntimeRegistry,
		n.P2P,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.RuntimeClient)
	runtimeClientAPI.RegisterService(n.grpcInternal.Server(), n.RuntimeClient)

	// Start workers (requires NodeController for checking, if nodes are synced).
	if err = n.startRuntimeWorkers(); err != nil {
		n.logger.Error("failed to start workers",
			"err", err,
		)
		return err
	}

	n.logger.Debug("runtime services started")

	return nil
}

func (n *Node) initRuntimeWorkers() error {
	dataDir := cmdCommon.DataDir()

	var err error

	genesisDoc, err := n.Genesis.GetGenesisDocument()
	if err != nil {
		return err
	}

	// Initialize the IAS proxy client.
	n.IAS, err = ias.New(n.Identity)
	if err != nil {
		n.logger.Error("failed to initialize IAS proxy client",
			"err", err,
		)
		return err
	}

	// Initialize the node's runtime registry.
	n.RuntimeRegistry, err = runtimeRegistry.New(n.svcMgr.Ctx, cmdCommon.DataDir(), n.Consensus, n.Identity, n.IAS)
	if err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.RuntimeRegistry, "runtime registry")
	storageAPI.RegisterService(n.grpcInternal.Server(), n.RuntimeRegistry.StorageRouter())

	// Initialize the P2P worker if any runtime mode is configured.
	// Since the P2P layer does not have a separate Start method and starts
	// listening immediately when created, make sure that we don't start it if
	// it is not needed.
	if n.RuntimeRegistry.Mode() != runtimeRegistry.RuntimeModeNone {
		p2pCtx, p2pSvc := service.NewContextCleanup(context.Background())
		if genesisDoc.Registry.Parameters.DebugAllowUnroutableAddresses {
			p2p.DebugForceAllowUnroutableAddresses()
		}
		n.P2P, err = p2p.New(p2pCtx, n.Identity, n.Consensus)
		if err != nil {
			return err
		}
		n.svcMgr.RegisterCleanupOnly(p2pSvc, "worker p2p")
	}

	// Initialize the common worker.
	n.CommonWorker, err = workerCommon.New(
		n,
		dataDir,
		n.Identity,
		n.Consensus,
		n.P2P,
		n.IAS,
		n.Consensus.KeyManager(),
		n.RuntimeRegistry,
		genesisDoc,
	)
	if err != nil {
		n.logger.Error("failed to initialize common worker",
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
		n.Consensus.Beacon(),
		n.Consensus.Registry(),
		n.Identity,
		n.Consensus,
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
		n.logger.Error("failed to initialize worker registration",
			"err", err,
		)
		return err
	}
	n.svcMgr.Register(n.RegistrationWorker)

	// Initialize the beacon worker.
	n.BeaconWorker, err = workerBeacon.New(
		n.Identity,
		n.Consensus,
		n.commonStore,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.BeaconWorker)

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

	// Commit storage settings to the registered runtimes.
	err = n.RuntimeRegistry.FinishInitialization(n.svcMgr.Ctx)
	if err != nil {
		return err
	}

	// Initialize the key manager worker.
	n.KeymanagerWorker, err = workerKeymanager.New(
		dataDir,
		n.CommonWorker,
		n.IAS,
		n.RegistrationWorker,
		n.Consensus.KeyManager(),
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.KeymanagerWorker)

	// Initialize the executor worker.
	n.ExecutorWorker, err = executor.New(
		dataDir,
		n.CommonWorker,
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

	// Initialize the public consensus services worker.
	n.ConsensusWorker, err = workerConsensusRPC.New(n.CommonWorker, n.RegistrationWorker)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.ConsensusWorker)

	return nil
}

func (n *Node) startRuntimeWorkers() error {
	// Start the common worker.
	if err := n.CommonWorker.Start(); err != nil {
		return err
	}

	// Start the runtime client service.
	if err := n.RuntimeClient.Start(); err != nil {
		return fmt.Errorf("failed to start runtime client service: %w", err)
	}

	// Start the storage worker.
	if err := n.StorageWorker.Start(); err != nil {
		return err
	}

	// Start the executor worker.
	if err := n.ExecutorWorker.Start(); err != nil {
		return err
	}

	// Start the key manager worker.
	if err := n.KeymanagerWorker.Start(); err != nil {
		return err
	}

	// Start the worker registration service.
	if err := n.RegistrationWorker.Start(); err != nil {
		return err
	}

	// Start the beacon worker.
	if err := n.BeaconWorker.Start(); err != nil {
		return err
	}

	// Start the sentry worker.
	if err := n.SentryWorker.Start(); err != nil {
		return err
	}

	// Start the public consensus services worker.
	if err := n.ConsensusWorker.Start(); err != nil {
		return fmt.Errorf("consensus worker: %w", err)
	}

	// Only start the external gRPC server if any workers are enabled.
	if n.StorageWorker.Enabled() ||
		n.KeymanagerWorker.Enabled() ||
		n.ConsensusWorker.Enabled() {
		if err := n.CommonWorker.Grpc.Start(); err != nil {
			n.logger.Error("failed to start external gRPC server",
				"err", err,
			)
			return err
		}
	}

	// Close readyCh once all workers and runtimes are initialized.
	go n.waitReady()

	return nil
}

func (n *Node) initGenesis() error {
	var err error
	n.Genesis, err = genesisFile.DefaultFileProvider()
	if err != nil {
		return fmt.Errorf("initGenesis: failed to create local genesis file provider: %w", err)
	}

	// Retrieve the genesis document and use it to configure the ChainID for
	// signature domain separation. We do this as early as possible.
	genesisDoc, err := n.Genesis.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("initGenesis: failed to get genesis: %w", err)
	}
	genesisDoc.SetChainContext()

	return nil
}

func (n *Node) dumpGenesis(ctx context.Context, blockHeight int64, epoch beacon.EpochTime) error {
	doc, err := n.Consensus.StateToGenesis(ctx, blockHeight)
	if err != nil {
		return fmt.Errorf("dumpGenesis: failed to get genesis: %w", err)
	}

	exportsDir := filepath.Join(cmdCommon.DataDir(), exportsSubDir)

	if err := common.Mkdir(exportsDir); err != nil {
		return fmt.Errorf("dumpGenesis: failed to create exports dir: %w", err)
	}

	filename := filepath.Join(exportsDir, fmt.Sprintf("genesis-%s-at-%d.json", doc.ChainID, doc.Height))
	if err := doc.WriteFileJSON(filename); err != nil {
		return fmt.Errorf("dumpGenesis: failed to write genesis file: %w", err)
	}

	return nil
}

// NewNode initializes and launches the Oasis node service.
//
// WARNING: This will misbehave iff cmd != RootCommand().  This is exposed
// for the benefit of tests and the interface is not guaranteed to be stable.
//
// Note: the reason for having the named err return value here is for the
// deferred func below to propagate the error.
func NewNode() (node *Node, err error) { // nolint: gocyclo
	logger := cmdCommon.Logger()

	node = &Node{
		svcMgr:  background.NewServiceManager(logger),
		readyCh: make(chan struct{}),
		logger:  logger,
	}

	var startOk bool
	defer func(node *Node) {
		if !startOk {
			if cErr := node.svcMgr.Ctx.Err(); cErr != nil {
				err = cErr
			}

			node.Stop()
			node.Cleanup()
		}
	}(node)

	if err = cmdCommon.Init(); err != nil {
		// Common stuff like logger not correctly initialized. Print to stderr
		_, _ = fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	// Log the version of the binary so that we can figure out what the
	// binary is from the logs.
	logger.Info("Starting oasis-node",
		"Version", version.SoftwareVersion,
	)

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory not configured")
		return nil, errors.New("data directory not configured")
	}

	// Load configured values for all registered crash points.
	crash.LoadViperArgValues()

	// Open the common node store.
	node.commonStore, err = persistent.NewCommonStore(dataDir)
	if err != nil {
		logger.Error("failed to open common node store",
			"err", err,
		)
		return nil, err
	}

	// Initialize upgrader backend and check if we can even launch.
	node.Upgrader, err = upgrade.New(node.commonStore, cmdCommon.DataDir())
	if err != nil {
		logger.Error("failed to initialize upgrade backend",
			"err", err,
		)
		return nil, err
	}
	if err = node.Upgrader.StartupUpgrade(); err != nil {
		logger.Error("error occurred during startup upgrade",
			"err", err,
		)
		return nil, err
	}

	// Generate/Load the node identity.
	signerFactory, err := cmdSigner.NewFactory(cmdSigner.Backend(), dataDir, identity.RequiredSignerRoles...)
	if err != nil {
		logger.Error("failed to initialize signer backend",
			"err", err,
		)
		return nil, err
	}
	node.Identity, err = identity.LoadOrGenerate(dataDir, signerFactory, false)
	if err != nil {
		logger.Error("failed to load/generate identity",
			"err", err,
		)
		return nil, err
	}

	logger.Info("loaded/generated node identity",
		"node_pk", node.Identity.NodeSigner.Public(),
		"p2p_pk", node.Identity.P2PSigner.Public(),
		"consensus_pk", node.Identity.ConsensusSigner.Public(),
		"tls_pk", node.Identity.GetTLSSigner().Public(),
	)

	// Initialize the internal gRPC server.
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

	// Start the metrics reporting server.
	if err = metrics.Start(); err != nil {
		logger.Error("failed to start metrics reporting server",
			"err", err,
		)
		return nil, err
	}

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
	if err = node.initGenesis(); err != nil {
		logger.Error("failed to initialize the genesis provider",
			"err", err,
		)
		return nil, err
	}

	logger.Info("starting Oasis node")

	// Initialize Tendermint consensus backend.
	node.Consensus, err = tendermint.New(node.svcMgr.Ctx, dataDir, node.Identity, node.Upgrader, node.Genesis)
	if err != nil {
		logger.Error("failed to initialize tendermint service",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(node.Consensus)
	consensusAPI.RegisterService(node.grpcInternal.Server(), node.Consensus)

	// Initialize the node controller.
	node.NodeController = control.New(node, node.Consensus, node.Upgrader)
	controlAPI.RegisterService(node.grpcInternal.Server(), node.NodeController)

	// If the consensus backend supports communicating with consensus services, we can also start
	// all services required for runtime operation.
	if node.Consensus.SupportedFeatures().Has(consensusAPI.FeatureServices) {
		if err = node.startRuntimeServices(); err != nil {
			logger.Error("failed to initialize runtime services",
				"err", err,
			)
			return nil, err
		}

		if flags.DebugDontBlameOasis() {
			// Initialize and start the debug controller if we are in debug mode.
			node.DebugController = control.NewDebug(node.Consensus)
			controlAPI.RegisterDebugService(node.grpcInternal.Server(), node.DebugController)
		}
	}

	// Start the internal gRPC server.
	if err = node.grpcInternal.Start(); err != nil {
		logger.Error("failed to start internal gRPC server",
			"err", err,
		)
		return nil, err
	}

	// Start the consensus backend service.
	if err = node.Consensus.Start(); err != nil {
		logger.Error("failed to start consensus backend service",
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
		cmdGrpc.ServerLocalFlags,
		cmdSigner.Flags,
		pprof.Flags,
		tendermint.Flags,
		seed.Flags,
		ias.Flags,
		workerKeymanager.Flags,
		runtimeRegistry.Flags,
		p2p.Flags,
		registration.Flags,
		runtimeClient.Flags,
		executor.Flags,
		workerCommon.Flags,
		workerStorage.Flags,
		workerSentry.Flags,
		workerConsensusRPC.Flags,
		crash.InitFlags(),
		badger.MigrationFlags,
	} {
		Flags.AddFlagSet(v)
	}
}
