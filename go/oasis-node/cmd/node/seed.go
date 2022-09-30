package node

import (
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	tmSeed "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/seed"
	controlApi "github.com/oasisprotocol/oasis-core/go/control/api"
	genesisApi "github.com/oasisprotocol/oasis-core/go/genesis/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
)

// SeedNode is the Oasis seed node service.
type SeedNode struct {
	logger *logging.Logger

	stopOnce sync.Once

	svcMgr       *background.ServiceManager
	grpcInternal *grpc.Server

	genesis  genesisApi.Provider
	identity *identity.Identity

	tendermintSeed *tmSeed.Service
}

// Wait waits for the node to gracefully terminate. Callers MUST
// call Cleanup() after wait returns.
func (n *SeedNode) Wait() {
	n.svcMgr.Wait()
}

// Stop gracefully terminates the seed node.
func (n *SeedNode) Stop() {
	n.stopOnce.Do(func() {
		n.svcMgr.Stop()
	})
}

// Cleanup cleans up after the node has terminated.
func (n *SeedNode) Cleanup() {
	n.svcMgr.Cleanup()
}

// NewSeedNode initializes the seed node.
func NewSeedNode() (node *SeedNode, err error) {
	logger := cmdCommon.Logger()

	node = &SeedNode{
		svcMgr: background.NewServiceManager(logger),
		logger: logger,
	}

	// Cleanup on error.
	defer func(node *SeedNode) {
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
	node.logger.Info("Starting Oasis seed node",
		"version", version.SoftwareVersion,
	)

	if err = verifyElevatedPrivileges(node.logger); err != nil {
		return nil, err
	}

	// Initialize the genesis provider.
	node.genesis, err = initGenesis(node.logger)
	if err != nil {
		return nil, err
	}

	// Configure a directory for the node to work in.
	dataDir, err := configureDataDir(node.logger)
	if err != nil {
		return nil, err
	}

	// Generate or load the node's identity.
	node.identity, err = loadOrGenerateIdentity(dataDir, node.logger)
	if err != nil {
		return nil, err
	}

	// Initialize the internal gRPC server.
	node.grpcInternal, err = cmdGrpc.NewServerLocal(false)
	if err != nil {
		node.logger.Error("failed to initialize internal gRPC server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(node.grpcInternal)

	// Register the node as a node controller.
	controlApi.RegisterService(node.grpcInternal.Server(), node)

	// Initialize and start services.
	node.tendermintSeed, err = tmSeed.New(dataDir, node.identity, node.genesis)
	if err != nil {
		return nil, err
	}
	node.svcMgr.Register(node.tendermintSeed)

	if err := node.tendermintSeed.Start(); err != nil {
		node.logger.Error("failed to start tendermint seed",
			"err", err,
		)
		return nil, err
	}

	// Start the internal gRPC server.
	if err := node.grpcInternal.Start(); err != nil {
		node.logger.Error("failed to start internal gRPC server",
			"err", err,
		)
		return nil, err
	}

	node.logger.Info("Seed node initialized and ready to serve")

	return node, nil
}
