package common

import (
	"io"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
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

	// LoggingFlags has the logging flags.
	loggingFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

func registerLoggingFlags(rootCmd *cobra.Command) {
	rootCmd.PersistentFlags().AddFlagSet(loggingFlags)
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

func init() {
	loggingFlags.String(cfgLogFile, "", "log file")
	loggingFlags.Var(&logFmt, cfgLogFmt, "log format")
	loggingFlags.Var(&logLevel, cfgLogLevel, "log level")

	_ = viper.BindPFlags(loggingFlags)
}
