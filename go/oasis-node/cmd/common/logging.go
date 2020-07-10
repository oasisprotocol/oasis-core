package common

import (
	"io"
	"os"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

const (
	cfgLogFile  = "log.file"
	cfgLogFmt   = "log.format"
	cfgLogLevel = "log.level"
	// Custom log levels for modules are not supported by cobra.
	// Use the config file (parsed by viper) instead.
)

// LoggingFlags has the logging flags.
var loggingFlags = flag.NewFlagSet("", flag.ContinueOnError)

func initLogging() error {
	logFile := viper.GetString(cfgLogFile)

	var logLevel logging.Level
	moduleLevels := map[string]logging.Level{}
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
		if w, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
			return err
		}
	}

	return logging.Initialize(w, logFmt, logLevel, moduleLevels)
}

func initLoggingFlags() {
	logFmt := logging.FmtLogfmt
	logLevel := logging.LevelWarn

	loggingFlags.String(cfgLogFile, "", "log file")
	loggingFlags.Var(&logFmt, cfgLogFmt, "log format")
	loggingFlags.Var(&logLevel, cfgLogLevel, "log level")

	_ = viper.BindPFlags(loggingFlags)
}
