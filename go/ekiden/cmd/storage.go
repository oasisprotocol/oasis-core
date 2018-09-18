package cmd

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage"
)

var (
	storageCmd = &cobra.Command{
		Use:   "storage",
		Short: "run storage node",
		Run:   storageNode,
	}

	storageLog = logging.GetLogger("storage")
)

type storageEnv struct {
	svcMgr  *backgroundServiceManager
	grpcSrv *grpcService
}

func storageNode(cmd *cobra.Command, args []string) {
	env := &storageEnv{
		svcMgr: newBackgroundServiceManager(),
	}
	defer func() { env.svcMgr.Cleanup() }()

	initCommon()

	storageLog.Info("starting ekiden storage node")

	if dataDir == "" {
		storageLog.Error("data directory not configured")
		return
	}

	var err error

	// Initialize the gRPC server.
	env.grpcSrv, err = newGrpcService(cmd)
	if err != nil {
		storageLog.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.grpcSrv)

	// Initialize the metrics server.
	metrics, err := newMetrics(cmd)
	if err != nil {
		storageLog.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := newPprofService(cmd)
	if err != nil {
		storageLog.Error("failed to initialize pprof server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(profiling)

	// Start the profiling server.
	if err = profiling.Start(); err != nil {
		storageLog.Error("failed to start pprof server",
			"err", err,
		)
		return
	}

	// Initialize the storage node backend.
	if err = initStorage(cmd, env); err != nil {
		storageLog.Error("failed to initialize backends",
			"err", err,
		)
		return
	}

	// Start metric server.
	if err = metrics.Start(); err != nil {
		storageLog.Error("failed to start metric server",
			"err", err,
		)
		return
	}

	// Start the gRPC server.
	if err = env.grpcSrv.Start(); err != nil {
		storageLog.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	storageLog.Info("initialization complete: ready to serve")

	// Wait for the services to catch on fire or otherwise
	// terminate.
	env.svcMgr.Wait()
}

func initStorage(cmd *cobra.Command, env *storageEnv) error {
	// Initialize the various backends.
	timeSource := epochtime.New()
	store, err := storage.New(cmd, timeSource, dataDir)
	if err != nil {
		return err
	}
	env.svcMgr.RegisterCleanupOnly(store)

	// Initialize and register the gRPC services.
	storage.NewGRPCServer(env.grpcSrv.s, store)

	storageLog.Debug("backends initialized")

	return nil
}

func init() {
	rootCmd.AddCommand(storageCmd)

	// Backend initialization flags.
	for _, v := range []func(*cobra.Command){
		registerMetricsFlags,
		registerGrpcFlags,
		registerPprofFlags,
		storage.RegisterFlags,
	} {
		v(storageCmd)
	}
}
