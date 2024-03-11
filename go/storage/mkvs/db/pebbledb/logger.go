package pebbledb

import (
	"fmt"
	"os"

	"github.com/cockroachdb/pebble"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

type pebbleLogger struct {
	logger *logging.Logger
}

func (pl *pebbleLogger) Infof(format string, args ...interface{}) {
	pl.logger.Info(fmt.Sprintf(format, args...))
}

func (pl *pebbleLogger) Errorf(format string, args ...interface{}) {
	pl.logger.Error("pebbledb error", "err", fmt.Sprintf(format, args...))
}

func (pl *pebbleLogger) Fatalf(format string, args ...interface{}) {
	pl.logger.Error("fatal pebbledb error", "err", fmt.Sprintf(format, args...))
	os.Exit(1)
}

func newPebbleLogger(module string) pebble.Logger {
	return &pebbleLogger{logger: logging.GetLoggerEx(module+"/pebble", 2)}
}
