// Package cmd implements the commands for the ekiden-node executable.
package cmd

import (
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

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
)

var (
	cfgFile  string
	dataDir  string
	logFile  string
	logFmt   string
	logLevel string

	abciAddr net.IP
	abciPort uint16

	rootCmd = &cobra.Command{
		Use:     "ekiden-node",
		Short:   "Ekiden node",
		Version: "0.2.0-alpha",
		Run:     rootMain,
	}

	rootLog = logging.GetLogger("ekiden-node")
)

// Execute spawns the main entry point after handling the config file
// and command line arguments.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logAndExit(err)
	}
}

func rootMain(cmd *cobra.Command, args []string) {
	initCommon()

	var cleanupFns []func()
	defer func() {
		rootLog.Debug("terminating, begining cleanup")

		for _, fn := range cleanupFns {
			fn()
		}

		rootLog.Debug("terminated")
	}()

	// XXX: Generate/Load the node identity.
	// Except tendermint does this on it's own, sigh.

	// Initialize the ABCI multiplexer.
	abciSockAddr := net.JoinHostPort(abciAddr.String(), strconv.Itoa(int(abciPort)))
	rootLog.Debug("ABCI Multiplexer Params", "addr", abciSockAddr)

	mux, err := abci.NewApplicationServer(abciSockAddr, dataDir)
	if err != nil {
		rootLog.Error("failed to initialize ABCI multiplexer",
			"err", err,
		)
		return
	}
	cleanupFns = append(cleanupFns, mux.Cleanup)

	// XXX: Register the various services with the ABCI multiplexer.
	_ = mux

	// Start the ABCI server.
	if err = mux.Start(); err != nil {
		rootLog.Error("failed to start ABCI multiplexer",
			"err", err,
		)
		return
	}

	// TODO: Spin up the tendermint node.
	// This should be in-process rather than fork() + exec() based.

	// Wait for the services to catch on fire or otherwise
	// terminate.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigCh:
		mux.Stop()
		break
	case <-mux.Quit():
		break
	}

	// Cleanup the mux (and mux-ed service) state.
	mux.Cleanup()
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

	for _, v := range []string{
		cfgABCIAddr,
		cfgABCIPort,
	} {
		viper.BindPFlag(v, rootCmd.Flags().Lookup(v))
	}
}
