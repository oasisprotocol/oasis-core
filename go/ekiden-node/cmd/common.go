package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/oasislabs/ekiden/go/common/logging"
	// TODO(willscott): wire in node for connectivity
	_ "github.com/oasislabs/ekiden/go/common/node"
	"github.com/spf13/viper"
)

func initCommon() {
	// Common initialization across all commands.
	initFns := []func() error{
		initDataDir,
		initLogging,
	}

	for _, fn := range initFns {
		if err := fn(); err != nil {
			logAndExit(err)
		}
	}

	rootLog.Debug("common initialization complete")
}

func initConfig() {
	if cfgFile != "" {
		// Read the config file if one is provided, otherwise
		// it is assumed that the combination of default values,
		// command line flags and env vars is sufficient.
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			logAndExit(err)
		}
	}

	// Force the DataDir to be an absolute path.
	var err error
	dataDir, err = filepath.Abs(viper.GetString(cfgDataDir))
	if err != nil {
		logAndExit(err)
	}

	// The command line flag values may be missing, but may be specified
	// from other sources, write back to the common flag vars for
	// convenience.
	viper.Set(cfgDataDir, dataDir)
	logFile = viper.GetString(cfgLogFile)
	logFmt = viper.GetString(cfgLogFmt)
	logLevel = viper.GetString(cfgLogLevel)
}

func initDataDir() error {
	const permDir = 0700

	fi, err := os.Lstat(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Make the directory.
			if err = os.MkdirAll(dataDir, permDir); err == nil {
				return nil
			}
		}
		return err
	}

	// Ensure the directory is actually a directory, with sufficiently
	// restrictive permissions.
	fm := fi.Mode()
	if !fm.IsDir() {
		return fmt.Errorf("init: datadir is not a directory")
	}
	if fm.Perm() != permDir {
		return fmt.Errorf("init: datadir has invalid permissions: %v", fm.Perm())
	}

	return nil
}

func initLogging() error {
	var w io.Writer = os.Stdout
	if logFile != "" {
		logFile = normalizePath(logFile)

		var err error
		if w, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err != nil {
			return err
		}
	}

	lvl, err := logging.LogLevel(logLevel)
	if err != nil {
		return err
	}
	f, err := logging.LogFormat(logFmt)
	if err != nil {
		return err
	}
	return logging.Initialize(w, lvl, f)
}

func logAndExit(err error) {
	fmt.Fprintln(os.Stderr, err) // nolint: errcheck
	os.Exit(1)
}

func normalizePath(f string) string {
	if !filepath.IsAbs(f) {
		f = filepath.Join(dataDir, f)
		return filepath.Clean(f)
	}
	return f
}
