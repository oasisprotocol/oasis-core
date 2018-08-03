// Package cmd implements the commands for the ekiden executable.
package cmd

import (
	"net"
	"strconv"

	"github.com/oasislabs/ekiden/go/beacon"
	"github.com/oasislabs/ekiden/go/epochtime"
	"github.com/oasislabs/ekiden/go/registry"
	"github.com/oasislabs/ekiden/go/scheduler"
	"github.com/oasislabs/ekiden/go/storage"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	tendermintEntry "github.com/tendermint/tendermint/cmd/tendermint/commands"

	"github.com/oasislabs/ekiden/go/common/logging"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgDataDir  = "datadir"
	cfgLogFile  = "log.file"
	cfgLogFmt   = "log.format"
	cfgLogLevel = "log.level"

	cfgABCIAddr    = "abci.address"
	cfgABCIPort    = "abci.port"
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
	abciAddr    net.IP
	abciPort    uint16
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
	svcMgr     *backgroundServiceManager
	grpcSrv    *grpcService
	tenderNode *tendermintAdapter
	abciMux    *abci.ApplicationServer
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

	// Initialize the ABCI multiplexer.
	abciAddr, _ = cmd.Flags().GetIP(cfgABCIAddr)
	abciPort, _ = cmd.Flags().GetUint16(cfgABCIPort)
	abciSockAddr := net.JoinHostPort(abciAddr.String(), strconv.Itoa(int(abciPort)))
	rootLog.Debug("ABCI Multiplexer Params", "addr", abciSockAddr)

	env.abciMux, err = abci.NewApplicationServer(abciSockAddr, dataDir)
	if err != nil {
		rootLog.Error("failed to initialize ABCI multiplexer",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.abciMux)

	env.tenderNode, err = newTendermintService(env.abciMux)
	if err != nil {
		rootLog.Error("failed to initialize tendermint",
			"err", err,
		)
		return
	}

	// Initialize the varous node backends.
	if err = initNode(cmd, env); err != nil {
		rootLog.Error("failed to initialize backends",
			"err", err,
		)
		return
	}

	// Start the ABCI server.
	if err = env.abciMux.Start(); err != nil {
		rootLog.Error("failed to start ABCI multiplexer",
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

	if err = env.tenderNode.Start(); err != nil {
		rootLog.Error("failed to start tendermint server",
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
	timeSource, err := epochtime.New(cmd)
	if err != nil {
		return err
	}
	randomBeacon := beacon.NewInsecureDummyRandomBeacon(timeSource)
	contractRegistry := registry.NewMemoryContractRegistry()
	entityRegistry := registry.NewMemoryEntityRegistry(timeSource)
	sched := scheduler.NewTrivialScheduler(timeSource, contractRegistry, entityRegistry, randomBeacon)
	store, err := storage.New(cmd, timeSource, dataDir)
	if err != nil {
		return err
	}
	env.svcMgr.RegisterCleanupOnly(store)

	// Initialize and register the gRPC services.
	epochtime.NewTimeSourceServer(env.grpcSrv.s, timeSource)
	beacon.NewRandomBeaconServer(env.grpcSrv.s, randomBeacon)
	registry.NewContractRegistryServer(env.grpcSrv.s, contractRegistry)
	registry.NewEntityRegistryServer(env.grpcSrv.s, entityRegistry)
	scheduler.NewSchedulerServer(env.grpcSrv.s, sched)
	storage.NewServer(env.grpcSrv.s, store)

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
	rootCmd.Flags().IPVar(&abciAddr, cfgABCIAddr, net.IPv4(127, 0, 0, 1), "ABCI server IP address")
	rootCmd.Flags().Uint16Var(&abciPort, cfgABCIPort, 26658, "ABCI server port")
	rootCmd.Flags().Uint16Var(&grpcPort, cfgGRPCPort, 9001, "gRPC server port")
	rootCmd.Flags().Uint16Var(&metricsPort, cfgMetricsPort, 3000, "metrics server port")

	for _, v := range []string{
		cfgABCIAddr,
		cfgABCIPort,
		cfgGRPCPort,
		cfgMetricsPort,
	} {
		viper.BindPFlag(v, rootCmd.Flags().Lookup(v))
	}

	// Backend initialization flags.
	for _, v := range []func(*cobra.Command){
		epochtime.RegisterFlags,
		storage.RegisterFlags,
		tendermintEntry.AddNodeFlags,
	} {
		v(rootCmd)
	}
}
