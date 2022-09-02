package host

import (
	"encoding/json"
	"strings"

	"github.com/go-kit/log"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

// Max number of bytes to buffer in the runtime log wrapper, i.e. roughly
// the longest expected valid log line from the runtime.
const maxLogBufferSize = 10_000_000

// RuntimeLogWrapper is a Writer that interprets data written to it as JSON-formatted
// runtime logs, and re-logs the messages as oasis-node logs. For example, it
// translates runtime log levels to oasis-node log levels, because the two have
// slightly different formats.
//
// It hardcodes some assumptions about the format of the runtime logs.
type RuntimeLogWrapper struct {
	// Logger for wrapper-internal info/errors.
	logger *logging.Logger
	// Loggers for the runtime, one for each module inside the runtime.
	rtLoggers map[string]*logging.Logger
	// Key-value pairs to append to each log entry.
	suffixes []interface{}
	// Buffer for accumulating incoming log entries from the runtime.
	buf []byte
}

// NewRuntimeLogWrapper creates a new RuntimeLogWrapper.
func NewRuntimeLogWrapper(logger *logging.Logger, suffixes ...interface{}) *RuntimeLogWrapper {
	return &RuntimeLogWrapper{
		logger:    logger,
		suffixes:  suffixes,
		rtLoggers: make(map[string]*logging.Logger),
	}
}

// Write implements io.Writer
func (w *RuntimeLogWrapper) Write(chunk []byte) (int, error) {
	w.buf = append(w.buf, chunk...)

	// Find and process any full lines that have accumulated in the buffer.
	// We assume one line per log entry.
	for i := len(w.buf) - len(chunk); i < len(w.buf); i++ {
		if w.buf[i] == '\n' {
			w.processLogLine(w.buf[:i])
			w.buf = w.buf[i+1:]
			i = 0
		}
	}

	// Prevent the buffer from growing indefinitely in case runtime logs
	// don't contain newlines (e.g. because of unexpected log format).
	if len(w.buf) > maxLogBufferSize {
		w.logger.Warn("runtime log buffer is too large, dropping logs")
		w.buf = w.buf[:0]
	}

	// Always report success. Even if log lines were malformed, we processed them
	// and reported the malformedness.
	return len(chunk), nil
}

// rtLogger returns the logger for the given module, creating it if needed.
func (w *RuntimeLogWrapper) rtLogger(module string) *logging.Logger {
	if l, ok := w.rtLoggers[module]; ok {
		return l
	}
	l := logging.GetBaseLogger(module).With(w.suffixes...)
	w.rtLoggers[module] = l
	return l
}

func (w RuntimeLogWrapper) processLogLine(line []byte) {
	// Interpret line as JSON.
	var m map[string]interface{}
	if err := json.Unmarshal(line, &m); err != nil {
		// If not valid JSON, forward line as normal log message with local timestamp.
		w.rtLogger("runtime").With("ts", log.DefaultTimestampUTC).Warn(string(line))
		return
	}

	// Destructure JSON into key-value pairs, parse common fields.
	var kv []interface{}
	var msg string
	var level string
	var module string
	for k, v := range m {
		if k == "msg" {
			if _msg, ok := v.(string); ok {
				msg = _msg
			} else {
				w.logger.Warn("malformed log line from runtime", "log_line", string(line), "err", "msg is not a string")
				return
			}
		} else if k == "level" {
			level, _ = v.(string)
		} else if k == "module" {
			module, _ = v.(string)
			if module == "" {
				module = "runtime"
			}
			// Enforce "runtime" scope in the module name.
			if !(module == "runtime" || strings.HasPrefix(module, "runtime/")) {
				module = "runtime/" + module
			}
		} else {
			kv = append(kv, k, v)
		}
	}

	// Output the log.
	rtLogger := w.rtLogger(module)
	switch level {
	case "DEBG":
		rtLogger.Debug(msg, kv...)
	case "INFO":
		rtLogger.Info(msg, kv...)
	case "WARN":
		rtLogger.Warn(msg, kv...)
	case "ERRO":
		rtLogger.Error(msg, kv...)
	default:
		w.logger.Warn("log line from runtime has no known error level set, using INFO", "log_line", string(line))
		rtLogger.Info(msg, kv...)
	}
}
