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
)

var (
	logFile  string
	logFmt   logging.Format
	logLevel logging.Level = logging.LevelWarn
)

func registerLoggingFlags(rootCmd *cobra.Command) {
	rootCmd.PersistentFlags().StringVar(&logFile, cfgLogFile, "", "log file")
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
	if err := logLevel.Set(viper.GetString(cfgLogLevel)); err != nil {
		return err
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

	return logging.Initialize(w, logLevel, logFmt)
}
