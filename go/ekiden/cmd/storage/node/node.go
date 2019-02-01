// Package node implements the storage node sub-command.
package node

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/background"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/metrics"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/pprof"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage"
)

var (
	nodeCmd = &cobra.Command{
		Use:   "node",
		Short: "run storage node",
		Run:   doNode,
	}

	logger = logging.GetLogger("cmd/storage/node")
)

type storageEnv struct {
	svcMgr  *background.ServiceManager
	grpcSrv *grpc.Server
}

func doNode(cmd *cobra.Command, args []string) {
	// Re-register flags due to https://github.com/spf13/viper/issues/233.
	RegisterFlags(cmd)

	env := &storageEnv{
		svcMgr: background.NewServiceManager(logger),
	}
	defer func() { env.svcMgr.Cleanup() }()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	logger.Info("starting ekiden storage node")

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory not configured")
		return
	}

	var err error

	// Initialize the gRPC server.
	env.grpcSrv, err = cmdGrpc.NewServerTCP()
	if err != nil {
		logger.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.grpcSrv)

	// Initialize the metrics server.
	metrics, err := metrics.New(env.svcMgr.Ctx)
	if err != nil {
		logger.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := pprof.New(env.svcMgr.Ctx)
	if err != nil {
		logger.Error("failed to initialize pprof server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(profiling)

	// Start the profiling server.
	if err = profiling.Start(); err != nil {
		logger.Error("failed to start pprof server",
			"err", err,
		)
		return
	}

	// Initialize the storage node backend.
	if err = initStorage(env, dataDir); err != nil {
		logger.Error("failed to initialize backends",
			"err", err,
		)
		return
	}

	// Start metric server.
	if err = metrics.Start(); err != nil {
		logger.Error("failed to start metric server",
			"err", err,
		)
		return
	}

	// Start the gRPC server.
	if err = env.grpcSrv.Start(); err != nil {
		logger.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	logger.Info("initialization complete: ready to serve")

	// Wait for the services to catch on fire or otherwise
	// terminate.
	env.svcMgr.Wait()
}

func initStorage(env *storageEnv, dataDir string) error {
	// Initialize the various backends.
	timeSource := epochtime.New()
	store, err := storage.New(timeSource, dataDir)
	if err != nil {
		return err
	}
	env.svcMgr.RegisterCleanupOnly(store, "storage backend")

	// Initialize and register the gRPC services.
	storage.NewGRPCServer(env.grpcSrv.Server(), store)

	logger.Debug("backends initialized")

	return nil
}

// RegisterFlags registers the flags used by the storage node sub-command.
func RegisterFlags(cmd *cobra.Command) {
	// Backend initialization flags.
	for _, v := range []func(*cobra.Command){
		metrics.RegisterFlags,
		cmdGrpc.RegisterServerTCPFlags,
		pprof.RegisterFlags,
		storage.RegisterFlags,
	} {
		v(cmd)
	}
}

// Register registers the storage node sub-command.
func Register(parentCmd *cobra.Command) {
	RegisterFlags(nodeCmd)
	parentCmd.AddCommand(nodeCmd)
}
