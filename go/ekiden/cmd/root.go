// Package cmd implements the commands for the ekiden executable.
package cmd

import (
	"crypto/rand"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/beacon"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
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
)

var (
	// Common config flags.
	cfgFile  string
	dataDir  string
	logFile  string
	logFmt   string
	logLevel string

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
	svcMgr   *backgroundServiceManager
	identity *signature.PrivateKey
	grpcSrv  *grpcService
	svcTmnt  service.TendermintService
}

func nodeMain(cmd *cobra.Command, args []string) {
	env := &nodeEnv{
		svcMgr: newBackgroundServiceManager(),
	}
	defer func() { env.svcMgr.Cleanup() }()

	initCommon()

	rootLog.Info("starting ekiden node")

	if dataDir == "" {
		rootLog.Error("data directory not configured")
		return
	}

	var err error

	// Generate/Load the node identity.
	env.identity, err = initIdentity(dataDir)
	if err != nil {
		rootLog.Error("failed to load/generate identity",
			"err", err,
		)
		return
	}

	// Initialize the gRPC server.
	env.grpcSrv, err = newGrpcService(cmd)
	if err != nil {
		rootLog.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.grpcSrv)

	// Initialize the metrics server.
	metrics, err := newMetrics(cmd)
	if err != nil {
		rootLog.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(metrics)

	// Initialize tendermint.
	env.svcTmnt = tendermint.New(cmd, dataDir, env.identity)
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

func initIdentity(dataDir string) (*signature.PrivateKey, error) {
	var k signature.PrivateKey

	if err := k.LoadPEM(filepath.Join(dataDir, "identity.pem"), rand.Reader); err != nil {
		return nil, err
	}

	rootLog.Info("loaded/generated node identity",
		"public_key", k.Public(),
	)

	return &k, nil
}

func initNode(cmd *cobra.Command, env *nodeEnv) error {
	// Initialize the various backends.
	timeSource, err := epochtime.New(cmd, env.svcTmnt)
	if err != nil {
		return err
	}
	randomBeacon, err := beacon.New(cmd, timeSource, env.svcTmnt)
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
	rootHash, err := roothash.New(cmd, timeSource, sched, store, reg, env.svcTmnt)
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

	for _, v := range []string{
		cfgDataDir,
		cfgLogFile,
		cfgLogFmt,
		cfgLogLevel,
	} {
		viper.BindPFlag(v, rootCmd.PersistentFlags().Lookup(v))
	}

	// Backend initialization flags.
	for _, v := range []func(*cobra.Command){
		registerMetricsFlags,
		registerGrpcFlags,
		beacon.RegisterFlags,
		epochtime.RegisterFlags,
		registry.RegisterFlags,
		roothash.RegisterFlags,
		scheduler.RegisterFlags,
		storage.RegisterFlags,
		tendermint.RegisterFlags,
	} {
		v(rootCmd)
	}
}
