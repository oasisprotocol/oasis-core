package logging

import (
	"github.com/go-kit/log"
)

// filterLogger is a logger wrapper that filters out specific keys.
type filterLogger struct {
	logger        log.Logger
	excludeFields map[any]struct{}
}

func (l *filterLogger) Log(keyvals ...any) error {
	if len(keyvals) == 0 {
		return nil
	}

	filteredKvs := make([]any, 0, len(keyvals))
	for i := 0; i < len(keyvals); i += 2 {
		if _, ok := l.excludeFields[keyvals[i]]; ok {
			continue
		}

		filteredKvs = append(filteredKvs, keyvals[i])
		if i+1 < len(keyvals) {
			filteredKvs = append(filteredKvs, keyvals[i+1])
		}
	}

	return l.logger.Log(filteredKvs...)
}

// NewFilterLogger creates a logger wrapper that filters out specific keys.
func NewFilterLogger(base *Logger, excludeFields map[any]struct{}) *Logger {
	return &Logger{
		logger: &filterLogger{
			logger:        base.logger,
			excludeFields: excludeFields,
		},
		level: base.level,
	}
}
