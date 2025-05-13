package logging

import (
	"io"

	"github.com/go-kit/log"
)

// NewJSONLogger creates a new logger which logs JSON-serialized logs directly to the given writer.
func NewJSONLogger(w io.Writer) *Logger {
	return &Logger{
		logger: log.NewJSONLogger(w),
	}
}
