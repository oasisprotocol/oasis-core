package common

import (
	"io"
	"os"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
)

func initLogging() error {
	logFile := config.GlobalConfig.Common.Log.File

	logLevel := logging.LevelWarn
	moduleLevels := map[string]logging.Level{}
	var err error
	for k, v := range config.GlobalConfig.Common.Log.Level {
		if k == "default" {
			if err = logLevel.Set(v); err != nil {
				return err
			}
			continue
		}

		var lvl logging.Level
		if err = lvl.Set(v); err != nil {
			return err
		}
		moduleLevels[k] = lvl
	}

	logFmt := logging.FmtLogfmt
	if config.GlobalConfig.Common.Log.Format != "" {
		if err = logFmt.Set(config.GlobalConfig.Common.Log.Format); err != nil {
			return err
		}
	}

	var w io.Writer = os.Stdout
	if logFile != "" {
		logFile = normalizePath(logFile)

		if w, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
			return err
		}
	}

	return logging.Initialize(w, logFmt, logLevel, moduleLevels)
}
