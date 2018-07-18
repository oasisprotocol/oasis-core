// Package cmd implements the commands for the ekiden executable.
package cmd

import (
	"net"
	"strconv"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/tendermint/abci"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgDataDir  = "datadir"
	cfgLogFile  = "log.file"
	cfgLogFmt   = "log.format"
	cfgLogLevel = "log.level"

	cfgABCIAddr = "abci.address"
	cfgABCIPort = "abci.port"

	cfgGRPCPort = "grpc.port"
)

var (
	cfgFile  string
	dataDir  string
	logFile  string
	logFmt   string
	logLevel string

	abciAddr net.IP
	abciPort uint16

	grpcPort uint16

	rootCmd = &cobra.Command{
		Use:     "ekiden",
		Short:   "Ekiden",
		Version: "0.2.0-alpha",
		Run:     rootMain,
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

func rootMain(cmd *cobra.Command, args []string) {
	svcMgr := newBackgroundServiceManager()
	defer func() { svcMgr.Cleanup() }()

	initCommon()

	rootLog.Info("starting ekiden node")

	// XXX: Generate/Load the node identity.
	// Except tendermint does this on it's own, sigh.

	// Initialize the gRPC server.
	grpcSrv, err := newGrpcService()
	if err != nil {
		rootLog.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	svcMgr.Register(grpcSrv)

	// Initialize the ABCI multiplexer.
	abciAddr, _ = cmd.Flags().GetIP(cfgABCIAddr)
	abciPort, _ = cmd.Flags().GetUint16(cfgABCIPort)
	abciSockAddr := net.JoinHostPort(abciAddr.String(), strconv.Itoa(int(abciPort)))
	rootLog.Debug("ABCI Multiplexer Params", "addr", abciSockAddr)

	mux, err := abci.NewApplicationServer(abciSockAddr, dataDir)
	if err != nil {
		rootLog.Error("failed to initialize ABCI multiplexer",
			"err", err,
		)
		return
	}
	svcMgr.Register(mux)

	// XXX: Register the various services with the ABCI multiplexer.
	_ = mux

	// Start the ABCI server.
	if err = mux.Start(); err != nil {
		rootLog.Error("failed to start ABCI multiplexer",
			"err", err,
		)
		return
	}

	// Start the gRPC server.
	if err = grpcSrv.Start(); err != nil {
		rootLog.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	// TODO: Spin up the tendermint node.
	// This should be in-process rather than fork() + exec() based.

	// Wait for the services to catch on fire or otherwise
	// terminate.
	svcMgr.Wait()
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
	rootCmd.PersistentFlags().Uint16Var(&grpcPort, cfgGRPCPort, 9001, "gRPC server port")
	rootCmd.MarkPersistentFlagRequired(cfgDataDir)

	for _, v := range []string{
		cfgDataDir,
		cfgLogFile,
		cfgLogFmt,
		cfgLogLevel,
		cfgGRPCPort,
	} {
		viper.BindPFlag(v, rootCmd.PersistentFlags().Lookup(v))
	}

	// Flags specific to the root command.
	rootCmd.Flags().IPVar(&abciAddr, cfgABCIAddr, net.IPv4(127, 0, 0, 1), "ABCI server IP address")
	rootCmd.Flags().Uint16Var(&abciPort, cfgABCIPort, 26658, "ABCI server port")

	for _, v := range []string{
		cfgABCIAddr,
		cfgABCIPort,
	} {
		viper.BindPFlag(v, rootCmd.Flags().Lookup(v))
	}
}
