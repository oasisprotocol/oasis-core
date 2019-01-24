package common

import (
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/logging"
)

const (
	cfgLogFile  = "log.file"
	cfgLogFmt   = "log.format"
	cfgLogLevel = "log.level"
	// Custom log levels for modules are not supported by cobra.
	// Use the config file (parsed by viper) instead.
)

var (
	logFmt   logging.Format
	logLevel logging.Level = logging.LevelWarn
)

func registerLoggingFlags(rootCmd *cobra.Command) {
	rootCmd.PersistentFlags().String(cfgLogFile, "", "log file")
	rootCmd.PersistentFlags().Var(&logFmt, cfgLogFmt, "log format")
	rootCmd.PersistentFlags().Var(&logLevel, cfgLogLevel, "log level")

	for _, v := range []string{
		cfgLogFile,
		cfgLogFmt,
		cfgLogLevel,
	} {
		_ = viper.BindPFlag(v, rootCmd.PersistentFlags().Lookup(v))
	}
}

func initLogging() error {
	logFile := viper.GetString(cfgLogFile)

	var logLevel logging.Level
	var moduleLevels = map[string]logging.Level{}
	if err := logLevel.Set(viper.GetString(cfgLogLevel)); err != nil {
		if errDefault := logLevel.Set(viper.GetString(cfgLogLevel + ".default")); errDefault != nil {
			return errDefault
		}

		for k, v := range viper.GetStringMapString(cfgLogLevel) {
			if k == "default" {
				continue
			}

			var lvl logging.Level
			if err = lvl.Set(v); err != nil {
				return err
			}
			moduleLevels[k] = lvl
		}
	}

	var logFmt logging.Format
	if err := logFmt.Set(viper.GetString(cfgLogFmt)); err != nil {
		return err
	}

	var w io.Writer = os.Stdout
	if logFile != "" {
		logFile = normalizePath(logFile)

		var err error
		if w, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err != nil {
			return err
		}
	}

	return logging.Initialize(w, logFmt, logLevel, moduleLevels)
}
