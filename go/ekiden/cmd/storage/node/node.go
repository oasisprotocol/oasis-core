// Package node implements the storage node sub-command.
package node

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/background"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
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

	logger = logging.GetLogger("storage/node")
)

type storageEnv struct {
	svcMgr  *background.ServiceManager
	grpcSrv *grpc.Server
}

func doNode(cmd *cobra.Command, args []string) {
	env := &storageEnv{
		svcMgr: background.NewServiceManager(logger),
	}
	defer func() { env.svcMgr.Cleanup() }()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	logger.Info("starting ekiden storage node")

	dataDir := cmdCommon.DataDir(cmd)
	if dataDir == "" {
		logger.Error("data directory not configured")
		return
	}

	var err error

	// Initialize the gRPC server.
	env.grpcSrv, err = grpc.NewServer(cmd)
	if err != nil {
		logger.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.grpcSrv)

	// Initialize the metrics server.
	metrics, err := metrics.New(cmd)
	if err != nil {
		logger.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := pprof.New(cmd)
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
	if err = initStorage(cmd, env, dataDir); err != nil {
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

func initStorage(cmd *cobra.Command, env *storageEnv, dataDir string) error {
	// Initialize the various backends.
	timeSource := epochtime.New()
	store, err := storage.New(cmd, timeSource, dataDir)
	if err != nil {
		return err
	}
	env.svcMgr.RegisterCleanupOnly(store)

	// Initialize and register the gRPC services.
	storage.NewGRPCServer(env.grpcSrv.Server(), store)

	logger.Debug("backends initialized")

	return nil
}

// Register registers the storage node sub-command.
func Register(parentCmd *cobra.Command) {
	// Backend initialization flags.
	for _, v := range []func(*cobra.Command){
		metrics.RegisterFlags,
		grpc.RegisterServerFlags,
		pprof.RegisterFlags,
		storage.RegisterFlags,
	} {
		v(nodeCmd)
	}

	parentCmd.AddCommand(nodeCmd)
}
