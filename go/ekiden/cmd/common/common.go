// Package common implements common ekiden command options and utilities.
package common

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
)

const (
	cfgConfigFile    = "config"
	cfgDataDir       = "datadir"
	cfgAllowTestKeys = "debug.allow_test_keys"
)

var (
	cfgFile string

	rootLog = logging.GetLogger("ekiden")
)

// DataDir retuns the data directory iff one is set.
func DataDir() string {
	return viper.GetString(cfgDataDir)
}

// DataDirOrPwd returns the data directory iff one is set, pwd otherwise.
func DataDirOrPwd() (string, error) {
	dataDir := DataDir()
	if dataDir == "" {
		var err error
		if dataDir, err = os.Getwd(); err != nil {
			return "", err
		}
	}
	return dataDir, nil
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
		initPublicKeyBlacklist,
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
	rootCmd.PersistentFlags().String(cfgDataDir, "", "data directory")
	rootCmd.PersistentFlags().Bool(cfgAllowTestKeys, false, "Allow test keys (UNSAFE)")

	for _, v := range []string{
		cfgConfigFile,
		cfgDataDir,
		cfgAllowTestKeys,
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

	dataDir := viper.GetString(cfgDataDir)

	// Force the DataDir to be an absolute path.
	if dataDir != "" {
		var err error
		dataDir, err = filepath.Abs(dataDir)
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
}

func initDataDir() error {
	dataDir := viper.GetString(cfgDataDir)
	if dataDir == "" {
		return nil
	}
	return common.Mkdir(dataDir)
}

func normalizePath(f string) string {
	if !filepath.IsAbs(f) {
		dataDir := viper.GetString(cfgDataDir)
		f = filepath.Join(dataDir, f)
		return filepath.Clean(f)
	}
	return f
}

func initPublicKeyBlacklist() error {
	allowTestKeys := viper.GetBool(cfgAllowTestKeys)
	signature.BuildPublicKeyBlacklist(allowTestKeys)
	ias.BuildMrsignerBlacklist(allowTestKeys)
	return nil
}

// GetOutputWriter will create a file if the config string is set,
// and otherwise return os.Stdout.
func GetOutputWriter(cmd *cobra.Command, cfg string) (io.WriteCloser, bool, error) {
	f, _ := cmd.Flags().GetString(cfg)
	if f == "" {
		return os.Stdout, false, nil
	}

	w, err := os.Create(f)
	return w, true, err
}

// GetInputReader will open a file if the config string is set,
// and otherwise return os.Stdin.
func GetInputReader(cmd *cobra.Command, cfg string) (io.ReadCloser, bool, error) {
	f, _ := cmd.Flags().GetString(cfg)
	if f == "" {
		return os.Stdin, false, nil
	}

	r, err := os.Open(f)
	return r, true, err
}
