package logging

import (
	"errors"

	"github.com/go-kit/log"
)

type multiLogger struct {
	loggers []log.Logger
}

func (l *multiLogger) Log(keyvals ...any) error {
	var mergedErr error
	for _, logger := range l.loggers {
		err := logger.Log(keyvals...)
		mergedErr = errors.Join(mergedErr, err)
	}
	return mergedErr
}

// NewMultiLogger creates a new multi logger which logs to extra logging backends in addition to
// the base one.
func NewMultiLogger(base *Logger, extra ...*Logger) *Logger {
	loggers := make([]log.Logger, 0, len(extra)+1)
	loggers = append(loggers, base.logger)
	for _, l := range extra {
		loggers = append(loggers, l.logger)
	}

	var logger log.Logger
	logger = &multiLogger{
		loggers: loggers,
	}
	if base.module != "" {
		logger = log.WithPrefix(logger, "module", base.module)
	}

	return &Logger{
		logger: logger,
		level:  base.level,
		module: base.module,
	}
}
