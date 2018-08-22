// Package cmd implements the commands for the ekiden executable.
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/beacon"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/epochtime"
	"github.com/oasislabs/ekiden/go/registry"
	"github.com/oasislabs/ekiden/go/roothash"
	"github.com/oasislabs/ekiden/go/scheduler"
	"github.com/oasislabs/ekiden/go/storage"
	"github.com/oasislabs/ekiden/go/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgDataDir  = "datadir"
	cfgLogFile  = "log.file"
	cfgLogFmt   = "log.format"
	cfgLogLevel = "log.level"

	cfgGRPCPort    = "grpc.port"
	cfgMetricsPort = "metrics.port"
)

var (
	// Common config flags.
	cfgFile  string
	dataDir  string
	logFile  string
	logFmt   string
	logLevel string

	// Root (aka node) command config flags.
	grpcPort    uint16
	metricsPort uint16

	rootCmd = &cobra.Command{
		Use:     "ekiden",
		Short:   "Ekiden",
		Version: "0.2.0-alpha",
		Run:     nodeMain,
	}

	rootLog = logging.GetLogger("ekiden")
)

// Execute spawns the main entry point after handling the config file
// and command line arguments.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logAndExit(err)
	}
}

type nodeEnv struct {
	svcMgr  *backgroundServiceManager
	grpcSrv *grpcService
	svcTmnt service.TendermintService
}

func nodeMain(cmd *cobra.Command, args []string) {
	env := &nodeEnv{
		svcMgr: newBackgroundServiceManager(),
	}
	defer func() { env.svcMgr.Cleanup() }()

	initCommon()

	rootLog.Info("starting ekiden node")

	var err error

	// XXX: Generate/Load the node identity.
	// Except tendermint does this on it's own, sigh.

	// Initialize the gRPC server.
	grpcPort, _ = cmd.Flags().GetUint16(cfgGRPCPort)
	env.grpcSrv, err = newGrpcService(grpcPort)
	if err != nil {
		rootLog.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.grpcSrv)

	// Initialize the metrics server.
	metricsPort, _ = cmd.Flags().GetUint16(cfgMetricsPort)
	metrics, err := newMetrics(metricsPort)
	if err != nil {
		rootLog.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(metrics)

	// Initialize tendermint.
	env.svcTmnt = tendermint.New(dataDir)
	env.svcMgr.Register(env.svcTmnt)

	// Initialize the varous node backends.
	if err = initNode(cmd, env); err != nil {
		rootLog.Error("failed to initialize backends",
			"err", err,
		)
		return
	}

	// Start metric server.
	if err = metrics.Start(); err != nil {
		rootLog.Error("failed to start metric server",
			"err", err,
		)
		return
	}

	// Start the tendermint service.
	//
	// Note: This will only start the node if it is required by
	// one of the backends.
	if err = env.svcTmnt.Start(); err != nil {
		rootLog.Error("failed to start tendermint service",
			"err", err,
		)
		return
	}

	// Start the gRPC server.
	if err = env.grpcSrv.Start(); err != nil {
		rootLog.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	rootLog.Info("initialization complete: ready to serve")

	// Wait for the services to catch on fire or otherwise
	// terminate.
	env.svcMgr.Wait()
}

func initNode(cmd *cobra.Command, env *nodeEnv) error {
	// Initialize the various backends.
	timeSource, err := epochtime.New(cmd, env.svcTmnt)
	if err != nil {
		return err
	}
	randomBeacon, err := beacon.New(cmd, timeSource)
	if err != nil {
		return err
	}
	reg, err := registry.New(cmd, timeSource, env.svcTmnt)
	if err != nil {
		return err
	}
	sched, err := scheduler.New(cmd, timeSource, reg, randomBeacon)
	if err != nil {
		return err
	}
	store, err := storage.New(cmd, timeSource, dataDir)
	if err != nil {
		return err
	}
	rootHash, err := roothash.New(cmd, sched, store, reg)
	if err != nil {
		return err
	}
	env.svcMgr.RegisterCleanupOnly(store)

	// Initialize and register the gRPC services.
	epochtime.NewGRPCServer(env.grpcSrv.s, timeSource)
	beacon.NewGRPCServer(env.grpcSrv.s, randomBeacon)
	registry.NewGRPCServer(env.grpcSrv.s, reg)
	roothash.NewGRPCServer(env.grpcSrv.s, rootHash)
	scheduler.NewGRPCServer(env.grpcSrv.s, sched)
	storage.NewGRPCServer(env.grpcSrv.s, store)

	rootLog.Debug("backends initialized")

	return nil
}

// nolint: errcheck
func init() {
	cobra.OnInitialize(initConfig)

	// Global flags common across all commands.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
	rootCmd.PersistentFlags().StringVar(&dataDir, cfgDataDir, "", "data directory")
	rootCmd.PersistentFlags().StringVar(&logFile, cfgLogFile, "", "log file")
	rootCmd.PersistentFlags().StringVar(&logFmt, cfgLogFmt, "Logfmt", "log format")
	rootCmd.PersistentFlags().StringVar(&logLevel, cfgLogLevel, "INFO", "log level")
	rootCmd.MarkPersistentFlagRequired(cfgDataDir)

	for _, v := range []string{
		cfgDataDir,
		cfgLogFile,
		cfgLogFmt,
		cfgLogLevel,
	} {
		viper.BindPFlag(v, rootCmd.PersistentFlags().Lookup(v))
	}

	// Flags specific to the root command.
	rootCmd.Flags().Uint16Var(&grpcPort, cfgGRPCPort, 9001, "gRPC server port")
	rootCmd.Flags().Uint16Var(&metricsPort, cfgMetricsPort, 3000, "metrics server port")

	for _, v := range []string{
		cfgGRPCPort,
		cfgMetricsPort,
	} {
		viper.BindPFlag(v, rootCmd.Flags().Lookup(v))
	}

	// Backend initialization flags.
	for _, v := range []func(*cobra.Command){
		beacon.RegisterFlags,
		epochtime.RegisterFlags,
		registry.RegisterFlags,
		roothash.RegisterFlags,
		scheduler.RegisterFlags,
		storage.RegisterFlags,
	} {
		v(rootCmd)
	}
}
