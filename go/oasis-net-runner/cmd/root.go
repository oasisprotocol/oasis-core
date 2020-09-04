// Package cmd implements commands for oasis-net-runner executable.
package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/oasis-net-runner/fixtures"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
)

const (
	cfgConfigFile  = "config"
	cfgLogFmt      = "log.format"
	cfgLogLevel    = "log.level"
	cfgLogNoStdout = "log.no_stdout"
)

var (
	rootCmd = &cobra.Command{
		Use:     "oasis-net-runner",
		Short:   "Oasis network runner",
		Version: version.SoftwareVersion,
		RunE:    runRoot,
	}

	dumpFixtureCmd = &cobra.Command{
		Use:   "dump-fixture",
		Short: "dump configured fixture to standard output",
		Run:   doDumpFixture,
	}

	rootFlags = flag.NewFlagSet("", flag.ContinueOnError)

	cfgFile string
)

// RootCmd returns the root command's structure that will be executed, so that
// it can be used to alter the configuration and flags of the command.
//
// Note: `Run` is pre-initialized to the main entry point of the test harness,
// and should likely be left un-altered.
func RootCmd() *cobra.Command {
	return rootCmd
}

// Execute spawns the main entry point after handing the config file.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initRootEnv(cmd *cobra.Command) (*env.Env, error) {
	// Initialize the root dir.
	rootDir := env.GetRootDir()
	if err := rootDir.Init(cmd); err != nil {
		return nil, err
	}
	env := env.New(rootDir)

	var ok bool
	defer func() {
		if !ok {
			env.Cleanup()
		}
	}()

	var logFmt logging.Format
	if err := logFmt.Set(viper.GetString(cfgLogFmt)); err != nil {
		return nil, fmt.Errorf("root: failed to set log format: %w", err)
	}

	var logLevel logging.Level
	if err := logLevel.Set(viper.GetString(cfgLogLevel)); err != nil {
		return nil, fmt.Errorf("root: failed to set log level: %w", err)
	}

	// Initialize logging.
	logFile := filepath.Join(env.Dir(), "net-runner.log")
	w, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("root: failed to open log file: %w", err)
	}

	var logWriter io.Writer = w
	if !viper.GetBool(cfgLogNoStdout) {
		logWriter = io.MultiWriter(os.Stdout, w)
	}
	if err := logging.Initialize(logWriter, logFmt, logLevel, nil); err != nil {
		return nil, fmt.Errorf("root: failed to initialize logging: %w", err)
	}

	ok = true
	return env, nil
}

func runRoot(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	// Initialize the base dir, logging, etc.
	rootEnv, err := initRootEnv(cmd)
	if err != nil {
		return err
	}
	defer rootEnv.Cleanup()
	logger := logging.GetLogger("net-runner")

	childEnv, err := rootEnv.NewChild("net-runner", nil)
	if err != nil {
		logger.Error("failed to setup child environment",
			"err", err,
		)
		return fmt.Errorf("root: failed to setup child environment: %w", err)
	}

	fixture, err := fixtures.GetFixture()
	if err != nil {
		return err
	}

	// Instantiate fixture.
	logger.Debug("instantiating fixture")
	net, err := fixture.Create(childEnv)
	if err != nil {
		logger.Error("failed to instantiate fixture",
			"err", err,
		)
		return fmt.Errorf("root: failed to instantiate fixture: %w", err)
	}

	// Start the network and keep it running.
	if err = net.Start(); err != nil {
		logger.Error("failed to start network",
			"err", err,
		)
		return fmt.Errorf("root: failed to start network: %w", err)
	}

	// Display information about where the client node socket is.
	if len(net.Clients()) > 0 {
		logger.Info("client node socket available",
			"path", net.Clients()[0].SocketPath(),
		)
	}

	// Wait for the network to stop.
	err = <-net.Errors()
	if err != nil {
		logger.Error("error while running network",
			"err", err,
		)
	}
	logger.Info("terminating network")

	return nil
}

func doDumpFixture(cmd *cobra.Command, args []string) {
	f, err := fixtures.GetFixture()
	if err != nil {
		common.EarlyLogAndExit(err)
	}

	// Encode fixture as JSON and dump it to stdout.
	data, err := fixtures.DumpFixture(f)
	if err != nil {
		common.EarlyLogAndExit(fmt.Errorf("doDumpFixture: failed to marshal fixture: %w", err))
	}
	fmt.Printf("%s", data)
}

func init() {
	common.SetBasicVersionTemplate(rootCmd)

	logFmt := logging.FmtLogfmt
	logLevel := logging.LevelInfo

	rootFlags.StringVar(&cfgFile, cfgConfigFile, "", "config file")
	rootFlags.Var(&logFmt, cfgLogFmt, "log format")
	rootFlags.Var(&logLevel, cfgLogLevel, "log level")
	rootFlags.Bool(cfgLogNoStdout, false, "do not mutiplex logs to stdout")
	_ = viper.BindPFlags(rootFlags)

	rootCmd.PersistentFlags().AddFlagSet(rootFlags)
	rootCmd.PersistentFlags().AddFlagSet(env.Flags)
	rootCmd.Flags().AddFlagSet(fixtures.DefaultFixtureFlags)
	rootCmd.Flags().AddFlagSet(fixtures.FileFixtureFlags)

	dumpFixtureCmd.Flags().AddFlagSet(fixtures.DefaultFixtureFlags)
	rootCmd.AddCommand(dumpFixtureCmd)

	cobra.OnInitialize(func() {
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
			if err := viper.ReadInConfig(); err != nil {
				common.EarlyLogAndExit(err)
			}
		}

		viper.Set(cmdFlags.CfgDebugDontBlameOasis, true)
	})
}
