// Package node implements the Oasis node.
package node

import (
	"context"
	"fmt"
	"sync"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft"
	cometbftAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusLightP2P "github.com/oasisprotocol/oasis-core/go/consensus/p2p/light"
	controlAPI "github.com/oasisprotocol/oasis-core/go/control/api"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	governanceAPI "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanagerAPI "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/p2p"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/provisioner"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	"github.com/oasisprotocol/oasis-core/go/sentry"
	sentryAPI "github.com/oasisprotocol/oasis-core/go/sentry/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	vaultAPI "github.com/oasisprotocol/oasis-core/go/vault/api"
	workerBeacon "github.com/oasisprotocol/oasis-core/go/worker/beacon"
	workerClient "github.com/oasisprotocol/oasis-core/go/worker/client"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor"
	workerKeymanager "github.com/oasisprotocol/oasis-core/go/worker/keymanager"
	workerRegistration "github.com/oasisprotocol/oasis-core/go/worker/registration"
	workerSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage"
)

// Node is the Oasis node service.
//
// WARNING: This is exposed for the benefit of tests and the interface
// is not guaranteed to be stable.
type Node struct {
	svcMgr       *background.ServiceManager
	grpcInternal *grpc.Server

	stopOnce sync.Once

	commonStore *persistent.CommonStore

	Consensus    consensusAPI.Service
	LightService consensusAPI.LightService

	dataDir      string
	chainContext string

	Upgrader upgradeAPI.Backend
	Identity *identity.Identity
	Sentry   sentryAPI.Backend

	RuntimeRegistry runtimeRegistry.Registry
	Provisioner     host.Provisioner

	CommonWorker       *workerCommon.Worker
	ExecutorWorker     *executor.Worker
	StorageWorker      *workerStorage.Worker
	ClientWorker       *workerClient.Worker
	SentryWorker       *workerSentry.Worker
	P2P                p2pAPI.Service
	RegistrationWorker *workerRegistration.Worker
	KeymanagerWorker   *workerKeymanager.Worker
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
	if err := n.WaitSync(context.Background()); err != nil {
		n.logger.Error("failed while waiting for node consensus sync", "err", err)
		return
	}

	// Wait for client worker.
	if n.ClientWorker.Enabled() {
		<-n.ClientWorker.Initialized()
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
func (n *Node) startRuntimeServices(genesisDoc *genesisAPI.Document, metricsEnabled bool) error {
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
	vaultAPI.RegisterService(grpcSrv, n.Consensus.Vault())

	// Initialize runtime workers.
	if err = n.initRuntimeWorkers(genesisDoc, metricsEnabled); err != nil {
		n.logger.Error("failed to initialize workers",
			"err", err,
		)
		return err
	}

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

func (n *Node) initRuntimeWorkers(genesisDoc *genesisAPI.Document, metricsEnabled bool) error {
	var err error

	// Initialize runtime provisioner.
	n.Provisioner, err = provisioner.New(n.dataDir, n.commonStore, n.Identity, n.Consensus, genesisDoc, metricsEnabled)
	if err != nil {
		return err
	}

	// Initialize the node's runtime registry.
	n.RuntimeRegistry, err = runtimeRegistry.New(n.dataDir, n.Consensus)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.RuntimeRegistry)

	// Initialize the common worker.
	n.CommonWorker, err = workerCommon.New(
		n,
		n.dataDir,
		n.chainContext,
		n.Identity,
		n.Consensus,
		n.LightService,
		n.P2P,
		n.Consensus.KeyManager(),
		n.RuntimeRegistry,
		n.Provisioner,
		metricsEnabled,
	)
	if err != nil {
		n.logger.Error("failed to initialize common worker",
			"err", err,
		)
		return err
	}
	n.svcMgr.Register(n.CommonWorker)

	workerCommonCfg := n.CommonWorker.GetConfig()

	// Initialize the registration worker.
	n.RegistrationWorker, err = workerRegistration.New(
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
		workerRegistration.DebugForceAllowUnroutableAddresses()
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
		n.RegistrationWorker,
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
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.StorageWorker)

	// Initialize the key manager worker.
	n.KeymanagerWorker, err = workerKeymanager.New(
		n.CommonWorker,
		n.RegistrationWorker,
		n.Consensus.KeyManager(),
		n.Provisioner,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.KeymanagerWorker)

	// Initialize the executor worker.
	n.ExecutorWorker, err = executor.New(
		n.CommonWorker,
		n.RegistrationWorker,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.ExecutorWorker)

	// Initialize the client worker.
	n.ClientWorker, err = workerClient.New(
		n.grpcInternal,
		n.CommonWorker,
		n.RegistrationWorker,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.ClientWorker)

	// Commit storage settings to the registered runtimes.
	err = n.RuntimeRegistry.FinishInitialization()
	if err != nil {
		return err
	}

	// Initialize the sentry worker.
	n.SentryWorker, err = workerSentry.New(
		n.Sentry,
		n.Identity,
	)
	if err != nil {
		return err
	}
	n.svcMgr.Register(n.SentryWorker)

	return nil
}

func (n *Node) startRuntimeWorkers() error {
	// Start the runtime registry.
	if err := n.RuntimeRegistry.Start(); err != nil {
		return err
	}

	// Start the common worker.
	if err := n.CommonWorker.Start(); err != nil {
		return err
	}

	// Start the runtime client worker.
	if err := n.ClientWorker.Start(); err != nil {
		return err
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

	// Close readyCh once all workers and runtimes are initialized.
	go n.waitReady()

	return nil
}

// NewNode initializes and launches the Oasis node service.
//
// WARNING: This will misbehave iff cmd != RootCommand().  This is exposed
// for the benefit of tests and the interface is not guaranteed to be stable.
//
// Note: the reason for having the named err return value here is for the
// deferred func below to propagate the error.
func NewNode(cfg *config.Config) (node *Node, err error) { // nolint: gocyclo
	logger := cmdCommon.Logger()

	node = &Node{
		svcMgr:  background.NewServiceManager(logger),
		readyCh: make(chan struct{}),
		logger:  logger,
	}

	// Cleanup on error.
	defer func(node *Node) {
		if err == nil {
			return
		}
		if cErr := node.svcMgr.Ctx.Err(); cErr != nil {
			err = cErr
		}
		node.Stop()
		node.Cleanup()
	}(node)

	// Initialize the common environment.
	if err = initCommon(); err != nil {
		return nil, err
	}

	// Log the version of the binary so that we can figure out what the
	// binary is from the logs.
	logger.Info("Starting oasis-node",
		"version", version.SoftwareVersion,
		"mode", cfg.Mode,
	)

	if err = verifyElevatedPrivileges(logger); err != nil {
		return nil, err
	}

	// Initialize the genesis provider.
	genesis := genesisFile.DefaultProvider()
	genesisDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		logger.Error("failed to get genesis document",
			"err", err,
		)
		return nil, err
	}
	genesisDoc.SetChainContext()
	node.chainContext = genesisDoc.ChainContext()

	// Configure a directory for the node to work in.
	node.dataDir, err = configureDataDir(logger)
	if err != nil {
		return nil, err
	}

	// Generate or load the node's identity.
	node.Identity, err = loadOrGenerateIdentity(node.dataDir, logger)
	if err != nil {
		return nil, err
	}

	// Load configured values for all registered crash points.
	crash.LoadViperArgValues()

	// Initialize and start the metrics reporting server.
	if _, err = startMetricServer(node.svcMgr, logger, &cfg.Metrics); err != nil {
		return nil, err
	}

	// Initialize and start the profiling server.
	if _, err = startProfilingServer(node.svcMgr, logger); err != nil {
		return nil, err
	}

	// Initialize the internal gRPC server.
	node.grpcInternal, err = cmdGrpc.NewServerLocal(false)
	if err != nil {
		logger.Error("failed to initialize internal gRPC server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(node.grpcInternal)

	// Register the node as a node controller.
	controlAPI.RegisterService(node.grpcInternal.Server(), node)

	// Open the common node store.
	node.commonStore, err = persistent.NewCommonStore(node.dataDir)
	if err != nil {
		logger.Error("failed to open common node store",
			"err", err,
		)
		return nil, err
	}

	metricsEnabled := metrics.Enabled(cfg.Metrics.Mode)

	// Initialize P2P network. Since libp2p host starts listening immediately when created, make
	// sure that we don't start it if it is not needed.
	if genesisDoc.Registry.Parameters.DebugAllowUnroutableAddresses {
		p2p.DebugForceAllowUnroutableAddresses()
	}

	isArchive := cfg.Mode == config.ModeArchive
	if isArchive {
		node.P2P = p2p.NewNop()
	} else {
		var p2pCfg p2p.Config
		if err := p2pCfg.Load(&cfg.P2P); err != nil {
			return nil, fmt.Errorf("failed to parse p2p config %w", err)
		}
		node.P2P, err = p2p.New(&p2pCfg, node.Identity, node.chainContext, node.commonStore)
		if err != nil {
			return nil, err
		}
	}
	node.svcMgr.Register(node.P2P)

	if err = node.P2P.Start(); err != nil {
		logger.Error("failed to start P2P service",
			"err", err,
		)
		return nil, err
	}

	// Initialize upgrader backend.
	node.Upgrader, err = upgrade.New(node.commonStore, node.dataDir, !isArchive)
	if err != nil {
		logger.Error("failed to initialize upgrade backend",
			"err", err,
		)
		return nil, err
	}
	// If not an archive mode, check if we can even launch.
	if !isArchive {
		if err = node.Upgrader.StartupUpgrade(); err != nil {
			logger.Error("error occurred during startup upgrade",
				"err", err,
			)
			return nil, err
		}
	}

	// Initialize consensus backend.
	switch backend := genesisDoc.Consensus.Backend; backend {
	case cometbftAPI.BackendName:
		node.Consensus, err = cometbft.New(node.svcMgr.Ctx, node.dataDir, node.Identity, node.Upgrader, genesis, genesisDoc, node.P2P, metricsEnabled)
		if err != nil {
			logger.Error("failed to initialize cometbft consensus backend",
				"err", err,
			)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported consensus backend: %s", backend)
	}
	node.svcMgr.Register(node.Consensus)
	consensusAPI.RegisterService(node.grpcInternal.Server(), node.Consensus)

	// Initialize CometBFT light client.
	node.LightService, err = cometbft.NewLightService(node.svcMgr.Ctx, genesisDoc, node.P2P)
	if err != nil {
		logger.Error("failed to initialize cometbft light client service",
			"err", err,
		)
		return nil, err
	}

	// Register consensus light client P2P protocol server.
	node.P2P.RegisterProtocolServer(consensusLightP2P.NewServer(node.P2P, node.chainContext, node.Consensus.Core()))

	// Register the consensus service with the peer registry.
	if mgr := node.P2P.PeerManager(); mgr != nil {
		if err = mgr.PeerRegistry().RegisterConsensus(node.chainContext, node.Consensus); err != nil {
			logger.Error("failed to register consensus with peer registry",
				"err", err,
			)
			return nil, err
		}
	}

	// If the consensus backend supports communicating with consensus services, we can also start
	// all services required for runtime operation.
	if node.Consensus.SupportedFeatures().Has(consensusAPI.FeatureServices) {
		if err = node.startRuntimeServices(genesisDoc, metricsEnabled); err != nil {
			logger.Error("failed to initialize runtime services",
				"err", err,
			)
			return nil, err
		}

		if flags.DebugDontBlameOasis() {
			// Register the node as a debug controller if we are in debug mode.
			controlAPI.RegisterDebugService(node.grpcInternal.Server(), node)

			// Enable direct storage access if we are in debug mode.
			storageAPI.RegisterService(node.grpcInternal.Server(), &debugStorage{node})
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

	return node, nil
}
