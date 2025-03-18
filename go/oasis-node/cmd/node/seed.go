package node

import (
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	cmtSeed "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/seed"
	controlApi "github.com/oasisprotocol/oasis-core/go/control/api"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/p2p"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

// SeedNode is the Oasis seed node service.
type SeedNode struct {
	logger *logging.Logger

	stopOnce sync.Once

	commonStore *persistent.CommonStore

	svcMgr       *background.ServiceManager
	grpcInternal *grpc.Server

	identity *identity.Identity

	cometbftSeed *cmtSeed.Service
	libp2pSeed   api.SeedService
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
	genesis := genesisFile.DefaultProvider()
	genesisDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		logger.Error("failed to get genesis document",
			"err", err,
		)
		return nil, err
	}
	genesisDoc.SetChainContext()

	// Configure a directory for the node to work in.
	dataDir, err := configureDataDir(node.logger)
	if err != nil {
		return nil, err
	}

	// Open the common node store.
	node.commonStore, err = persistent.NewCommonStore(dataDir)
	if err != nil {
		logger.Error("failed to open common node store",
			"err", err,
		)
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

	// Initialize and start the CometBFT seed.
	node.cometbftSeed, err = cmtSeed.New(dataDir, node.identity, genesisDoc)
	if err != nil {
		return nil, err
	}
	node.svcMgr.Register(node.cometbftSeed)

	if err = node.cometbftSeed.Start(); err != nil {
		node.logger.Error("failed to start cometbft seed",
			"err", err,
		)
		return nil, err
	}

	// Initialize and start the libp2p seed.
	var seedCfg p2p.SeedConfig
	if err = seedCfg.Load(); err != nil {
		return nil, fmt.Errorf("failed to load libp2p seed config: %w", err)
	}
	seedCfg.Signer = node.identity.P2PSigner
	seedCfg.CommonStore = node.commonStore

	node.libp2pSeed, err = p2p.NewSeedNode(&seedCfg)
	if err != nil {
		return nil, err
	}
	node.svcMgr.Register(node.libp2pSeed)

	if err := node.libp2pSeed.Start(); err != nil {
		node.logger.Error("failed to start libp2p seed",
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
