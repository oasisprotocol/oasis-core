// Package logging implements support for structured logging.
//
// This package is inspired heavily by go-logging, kit/log and the
// tendermint libs/log packages, and is oriented towards making
// the structured logging experience somewhat easier to use.
package logging

import (
	"fmt"
	"io"
	"io/ioutil"
	goLog "log"
	"sort"
	"strings"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/spf13/pflag"

	goLogging "github.com/whyrusleeping/go-logging"
)

var (
	backend = logBackend{
		baseLogger:   log.NewNopLogger(),
		defaultLevel: LevelError,
	}

	_ pflag.Value = (*Level)(nil)
	_ pflag.Value = (*Format)(nil)
)

// Format is a logging format.
type Format uint

const (
	// FmtLogfmt is the "logfmt" logging format.
	FmtLogfmt Format = iota
	// FmtJSON is the JSON logging format.
	FmtJSON
)

// String returns the string representation of a Format.
func (f *Format) String() string {
	switch *f {
	case FmtLogfmt:
		return "logfmt"
	case FmtJSON:
		return "JSON"
	default:
		panic("logging: unsupported format")
	}
}

// Set sets the Format to the value specified by the provided string.
func (f *Format) Set(s string) error {
	switch strings.ToUpper(s) {
	case "LOGFMT":
		*f = FmtLogfmt
	case "JSON":
		*f = FmtJSON
	default:
		return fmt.Errorf("logging: invalid log format: '%s'", s)
	}

	return nil
}

// Type returns the list of supported Formats.
func (f *Format) Type() string {
	return "[logfmt,JSON]"
}

// Level is a log level.
type Level uint

const (
	// LevelDebug is the log level for debug messages.
	LevelDebug Level = iota
	// LevelInfo is the log level for informative messages.
	LevelInfo
	// LevelWarn is the log level for warning messages.
	LevelWarn
	// LevelError is the log level for error messages.
	LevelError
)

func (l Level) toOption() level.Option {
	switch l {
	case LevelDebug:
		return level.AllowDebug()
	case LevelInfo:
		return level.AllowInfo()
	case LevelWarn:
		return level.AllowWarn()
	case LevelError:
		return level.AllowError()
	default:
		panic("logging: unsupported log level")
	}
}

// String returns the string representation of a Level.
func (l *Level) String() string {
	switch *l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		panic("logging: unsupported log level")
	}
}

// Set sets the Level to the value specified by the provided string.
func (l *Level) Set(s string) error {
	switch strings.ToUpper(s) {
	case "DEBUG":
		*l = LevelDebug
	case "INFO":
		*l = LevelInfo
	case "WARN":
		*l = LevelWarn
	case "ERROR":
		*l = LevelError
	default:
		return fmt.Errorf("logging: invalid log level: '%s'", s)
	}

	return nil
}

// Type returns the list of supported Levels.
func (l *Level) Type() string {
	return "[DEBUG,INFO,WARN,ERROR]"
}

// Logger is a logger instance.
type Logger struct {
	logger log.Logger
	level  Level
	module string
}

// Debug logs the message and key value pairs at the Debug log level.
func (l *Logger) Debug(msg string, keyvals ...interface{}) {
	if l.level > LevelDebug {
		return
	}
	keyvals = append([]interface{}{"msg", msg}, keyvals...)
	_ = level.Debug(l.logger).Log(keyvals...)
}

// Info logs the message and key value pairs at the Info log level.
func (l *Logger) Info(msg string, keyvals ...interface{}) {
	if l.level > LevelInfo {
		return
	}
	keyvals = append([]interface{}{"msg", msg}, keyvals...)
	_ = level.Info(l.logger).Log(keyvals...)
}

// Warn logs the message and key value pairs at the Warn log level.
func (l *Logger) Warn(msg string, keyvals ...interface{}) {
	if l.level > LevelWarn {
		return
	}
	keyvals = append([]interface{}{"msg", msg}, keyvals...)
	_ = level.Warn(l.logger).Log(keyvals...)
}

// Error logs the message and key value pairs at the Error log level.
func (l *Logger) Error(msg string, keyvals ...interface{}) {
	if l.level > LevelError {
		return
	}
	keyvals = append([]interface{}{"msg", msg}, keyvals...)
	_ = level.Error(l.logger).Log(keyvals...)
}

// With returns a clone of the logger with the provided key/value pairs
// added via log.WithPrefix.
func (l *Logger) With(keyvals ...interface{}) *Logger {
	return &Logger{
		logger: log.With(l.logger, keyvals...),
		level:  l.level,
	}
}

// GetLevel returns the current global log level.
func GetLevel() Level {
	return backend.defaultLevel
}

// GetLogger creates a new logger instance with the specified module.
//
// This may be called from any point, including before Initialize is
// called, allowing for the construction of a package level Logger.
func GetLogger(module string) *Logger {
	return backend.getLogger(module, 0)
}

// GetLoggerEx creates a new logger instance with the specified module,
// using the specified extra levels of stack unwinding when determining
// a caller.
//
// The GetLogger call is equivalent to GetLoggerEx with an extraUnwind
// of 0.  This routine is primarily intended to facilitate writing
// additional logging wrappers.
func GetLoggerEx(module string, extraUnwind int) *Logger {
	return backend.getLogger(module, extraUnwind)
}

// Initialize initializes the logging backend to write to the provided
// Writer with the given format and log levels specified for each
// module. If the requested module is not given, default level is
// taken. If the Writer is nil, all log output will be silently discarded.
func Initialize(w io.Writer, format Format, defaultLvl Level, moduleLvls map[string]Level) error {
	backend.Lock()
	defer backend.Unlock()

	if backend.initialized {
		return fmt.Errorf("logging: already initialized")
	}

	var logger log.Logger = backend.baseLogger
	if w != nil {
		w = log.NewSyncWriter(w)
		switch format {
		case FmtLogfmt:
			logger = log.NewLogfmtLogger(w)
		case FmtJSON:
			logger = log.NewJSONLogger(w)
		default:
			return fmt.Errorf("logging: unsupported log format: %v", format)
		}
	}

	logger = level.NewFilter(logger, defaultLvl.toOption())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)

	backend.baseLogger = logger
	backend.moduleLevels = moduleLvls
	backend.defaultLevel = defaultLvl
	backend.initialized = true

	// Swap all the early loggers to the initialized backend.
	for _, l := range backend.earlyLoggers {
		l.swapLogger.Swap(backend.baseLogger)

		// Re-evaluate log level.
		// NOTE: This introduces a potential race condition if loggers are used
		//       before the logging system is initialized. Protecting the log
		//       level with a mutex just for this one case seems overkill.
		backend.setupLogLevelLocked(l.logger)
	}
	backend.earlyLoggers = nil

	// libp2p/IPFS uses yet another logging library, that appears to be a
	// wrapper around go-logging.  Because it's quality IPFS code, it's
	// configured via env vars, from the package `init()`.
	//
	// Till we can write a nice wrapper around it, to make it do what we
	// want, reach into the underlying library and squelch it.
	goLogging.Reset()
	_ = goLogging.SetBackend(goLogging.NewLogBackend(ioutil.Discard, "libp2p", goLog.LstdFlags))

	return nil
}

type earlyLogger struct {
	swapLogger *log.SwapLogger
	logger     *Logger
}

type logBackend struct {
	sync.Mutex

	baseLogger   log.Logger
	earlyLoggers []*earlyLogger
	defaultLevel Level
	moduleLevels map[string]Level

	initialized bool
}

func (b *logBackend) setupLogLevelLocked(l *Logger) {
	// Check, whether there is a specific logging level set for the module.
	// The longest prefix match of the module name provided in the config file will be taken.
	// Otherwise, fallback to level defined by "default" key.
	modulePrefixes := make([]string, 0, len(b.moduleLevels))
	for k := range b.moduleLevels {
		modulePrefixes = append(modulePrefixes, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(modulePrefixes)))

	lvl := b.defaultLevel
	for _, k := range modulePrefixes {
		if strings.HasPrefix(l.module, k) {
			lvl = b.moduleLevels[k]
			break
		}
	}

	l.level = lvl
}

func (b *logBackend) getLogger(module string, extraUnwind int) *Logger {
	// The default unwind depth is as log.DefaultCaller, with an
	// additional level of stack unwinding due to this module's
	// leveling wrapper.
	const defaultUnwind = 4

	b.Lock()
	defer b.Unlock()

	logger := b.baseLogger
	if !b.initialized {
		logger = &log.SwapLogger{}
	}

	var keyvals []interface{}
	if module != "" {
		keyvals = append(keyvals, []interface{}{
			"module",
			module,
		}...)
	}
	keyvals = append(keyvals, []interface{}{
		"caller",
		log.Caller(defaultUnwind + extraUnwind),
	}...)
	l := &Logger{
		logger: log.WithPrefix(logger, keyvals...),
		module: module,
	}
	b.setupLogLevelLocked(l)

	if !b.initialized {
		// Stash the logger so that it can be instantiated once logging
		// is actually initialized.
		sLog := logger.(*log.SwapLogger)
		b.earlyLoggers = append(b.earlyLoggers, &earlyLogger{swapLogger: sLog, logger: l})
	}

	return l
}
