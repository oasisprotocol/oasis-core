package cmd

import (
	"github.com/oasislabs/ekiden/go/epochtime"
	"github.com/oasislabs/ekiden/go/registry"

	"github.com/spf13/cobra"
)

var (
	dummyCmd = &cobra.Command{
		Use:   "dummy",
		Short: "Start the dummy node",
		Long:  "Centralized (mock) services, accessible via gRPC",
		Run:   dummyMain,
	}
)

func dummyMain(cmd *cobra.Command, args []string) {
	svcMgr := newBackgroundServiceManager()
	defer func() { svcMgr.Cleanup() }()

	initCommon()

	rootLog.Info("starting dummy node")

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
	rootCmd.AddCommand(dummyCmd)
}
