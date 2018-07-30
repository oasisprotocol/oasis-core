package cmd

import (
	"path/filepath"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/epochtime"
	"github.com/oasislabs/ekiden/go/registry"
	adapter "github.com/oasislabs/ekiden/go/tendermint/abci"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	tendermintEntry "github.com/tendermint/tendermint/cmd/tendermint/commands"
	tendermintConfig "github.com/tendermint/tendermint/config"
	tendermintNode "github.com/tendermint/tendermint/node"
)

var (
	tendermintCmd = &cobra.Command{
		Use:   "node",
		Short: "Start a bft node",
		Long:  "Tendemrint-coordinating services, accessible via gRPC",
		Run:   dummyMain,
	}
)

// Adapter for tendermint Nodes to be managed by the ekiden service mux
type nodeAdapter struct {
	*tendermintNode.Node
}

func (n *nodeAdapter) Stop() {
	n.Stop()
}

func (n *nodeAdapter) Cleanup() {
	_ = n.Reset()
}

func tenderCmd(cmd *cobra.Command, args []string) {
	svcMgr := newBackgroundServiceManager()
	defer func() { svcMgr.Cleanup() }()

	initCommon()

	rootLog.Info("starting tendermint node")

	// Force the DataDir to be an absolute path.
	var err error
	dataDir, err = filepath.Abs(viper.GetString(cfgDataDir))
	if err != nil {
		logAndExit(err)
	}

	tenderConfig := tendermintConfig.DefaultConfig()
	viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(dataDir)
	tenderLog := &adapter.LogAdapter{logging.GetLogger("tendermint")}
	node, err := tendermintNode.DefaultNewNode(tenderConfig, tenderLog)
	if err != nil {
		logAndExit(err)
	}
	svcMgr.Register(&nodeAdapter{node})

	// Start the tendermint node
	if err = node.Start(); err != nil {
		rootLog.Error("failed to start tendermint",
			"err", err,
		)
		return
	}

	// Initialize the gRPC server.
	grpcSrv, err := newGrpcService()
	if err != nil {
		rootLog.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	svcMgr.Register(grpcSrv)

	// Initialize the various backends.
	timeSource := epochtime.NewMockTimeSource()
	entityRegistry := registry.NewMemoryEntityRegistry(timeSource)

	// Initialize and register the gRPC services.
	epochtime.NewTimeSourceServer(grpcSrv.s, timeSource)
	registry.NewEntityRegistryServer(grpcSrv.s, entityRegistry)

	// Start the gRPC server.
	if err = grpcSrv.Start(); err != nil {
		rootLog.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	// Wait for the services to catch on fire or otherwise
	// terminate.
	svcMgr.Wait()
}

func init() {
	tendermintEntry.AddNodeFlags(tendermintCmd)
	rootCmd.AddCommand(tendermintCmd)
}
