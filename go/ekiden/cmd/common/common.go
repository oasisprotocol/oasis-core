// Package common implements common ekiden command options and utilities.
package common

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/logging"
)

const (
	cfgConfigFile = "config"
	cfgDataDir    = "datadir"
)

var (
	cfgFile string
	dataDir string

	rootLog = logging.GetLogger("ekiden")
)

// DataDir retuns the data directory iff one is set.
func DataDir(cmd *cobra.Command) string {
	d, _ := cmd.Flags().GetString(cfgDataDir)
	return d
}

// EarlyLogAndExit logs the error and exits.
//
// Note: This routine should only be used prior to the logging system
// being initialized.
func EarlyLogAndExit(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// Init initializes the common environment across all commands.
func Init() error {
	initFns := []func() error{
		initDataDir,
		initLogging,
	}

	for _, fn := range initFns {
		if err := fn(); err != nil {
			return err
		}
	}

	rootLog.Debug("common initialization complete")

	return nil
}

// Logger returns the command logger.
func Logger() *logging.Logger {
	return rootLog
}

// RegisterRootFlags registers the persistent flags that are common
// across all commands.
func RegisterRootFlags(rootCmd *cobra.Command) {
	rootCmd.PersistentFlags().StringVar(&cfgFile, cfgConfigFile, "", "config file")
	rootCmd.PersistentFlags().StringVar(&dataDir, cfgDataDir, "", "data directory")

	for _, v := range []string{
		cfgConfigFile,
		cfgDataDir,
	} {
		_ = viper.BindPFlag(v, rootCmd.PersistentFlags().Lookup(v))
	}

	registerLoggingFlags(rootCmd)
}

// InitConfig initializes the command configuration.
//
// WARNING: This is exposed for the benefit of tests and the interface
// is not guaranteed to be stable.
func InitConfig() {
	if cfgFile != "" {
		// Read the config file if one is provided, otherwise
		// it is assumed that the combination of default values,
		// command line flags and env vars is sufficient.
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			EarlyLogAndExit(err)
		}
	}

	// Force the DataDir to be an absolute path.
	if dataDir != "" {
		var err error
		dataDir, err = filepath.Abs(viper.GetString(cfgDataDir))
		if err != nil {
			EarlyLogAndExit(err)
		}
	}

	// The command line flag values may be missing, but may be specified
	// from other sources, write back to the common flag vars for
	// convenience.
	//
	// Note: This is only for flags that are common across all
	// sub-commands, so excludes things such as the gRPC/Metrics/etc
	// configuration.
	viper.Set(cfgDataDir, dataDir)
	viper.Set(cfgLogFile, logFile)
	viper.Set(cfgLogFmt, logFmt)
	logFile = viper.GetString(cfgLogFile)
}

func initDataDir() error {
	if dataDir == "" {
		return nil
	}
	return common.Mkdir(dataDir)
}

func normalizePath(f string) string {
	if !filepath.IsAbs(f) {
		f = filepath.Join(dataDir, f)
		return filepath.Clean(f)
	}
	return f
}
