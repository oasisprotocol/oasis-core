package logging

import (
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"go.uber.org/zap/zapcore"
)

// objectEncoder is an ObjectEncoder backed by a memory array inspired by
// https://github.com/uber-go/zap/blob/6f34060764b5ea1367eecda380ba8a9a0de3f0e6/zapcore/memory_encoder.go#L28.
type objectEncoder struct {
	// fields contains the entire encoded log context.
	fields []interface{}

	// Current namespace.
	currNs string
}

// AddArray implements ObjectEncoder.
func (m *objectEncoder) AddArray(key string, v zapcore.ArrayMarshaler) error {
	arr := &sliceArrayEncoder{elems: make([]interface{}, 0)}
	if err := v.MarshalLogArray(arr); err != nil {
		return err
	}
	m.fields = append(m.fields, key, arr.elems)
	return nil
}

// AddObject implements ObjectEncoder.
func (m *objectEncoder) AddObject(k string, v zapcore.ObjectMarshaler) error {
	newMap := &objectEncoder{}
	if err := v.MarshalLogObject(newMap); err != nil {
		return err
	}
	m.fields = append(m.fields, m.namespaced(k), newMap.fields)
	return nil
}

// AddBinary implements ObjectEncoder.
func (m *objectEncoder) AddBinary(k string, v []byte) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddByteString implements ObjectEncoder.
func (m *objectEncoder) AddByteString(k string, v []byte) {
	m.fields = append(m.fields, m.namespaced(k), string(v))
}

// AddBool implements ObjectEncoder.
func (m *objectEncoder) AddBool(k string, v bool) { m.fields = append(m.fields, m.namespaced(k), v) }

// AddDuration implements ObjectEncoder.
func (m *objectEncoder) AddDuration(k string, v time.Duration) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddComplex128 implements ObjectEncoder.
func (m *objectEncoder) AddComplex128(k string, v complex128) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddComplex64 implements ObjectEncoder.
func (m *objectEncoder) AddComplex64(k string, v complex64) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddFloat64 implements ObjectEncoder.
func (m *objectEncoder) AddFloat64(k string, v float64) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddFloat32 implements ObjectEncoder.
func (m *objectEncoder) AddFloat32(k string, v float32) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddInt implements ObjectEncoder.
func (m *objectEncoder) AddInt(k string, v int) { m.fields = append(m.fields, m.namespaced(k), v) }

// AddInt64 implements ObjectEncoder.
func (m *objectEncoder) AddInt64(k string, v int64) { m.fields = append(m.fields, m.namespaced(k), v) }

// AddInt32 implements ObjectEncoder.
func (m *objectEncoder) AddInt32(k string, v int32) { m.fields = append(m.fields, m.namespaced(k), v) }

// AddInt16 implements ObjectEncoder.
func (m *objectEncoder) AddInt16(k string, v int16) { m.fields = append(m.fields, m.namespaced(k), v) }

// AddInt8 implements ObjectEncoder.
func (m *objectEncoder) AddInt8(k string, v int8) { m.fields = append(m.fields, m.namespaced(k), v) }

// AddString implements ObjectEncoder.
func (m *objectEncoder) AddString(k string, v string) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddTime implements ObjectEncoder.
func (m *objectEncoder) AddTime(k string, v time.Time) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddUint implements ObjectEncoder.
func (m *objectEncoder) AddUint(k string, v uint) { m.fields = append(m.fields, m.namespaced(k), v) }

// AddUint64 implements ObjectEncoder.
func (m *objectEncoder) AddUint64(k string, v uint64) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddUint32 implements ObjectEncoder.
func (m *objectEncoder) AddUint32(k string, v uint32) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddUint16 implements ObjectEncoder.
func (m *objectEncoder) AddUint16(k string, v uint16) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddUint8 implements ObjectEncoder.
func (m *objectEncoder) AddUint8(k string, v uint8) { m.fields = append(m.fields, m.namespaced(k), v) }

// AddUintptr implements ObjectEncoder.
func (m *objectEncoder) AddUintptr(k string, v uintptr) {
	m.fields = append(m.fields, m.namespaced(k), v)
}

// AddReflected implements ObjectEncoder.
func (m *objectEncoder) AddReflected(k string, v interface{}) error {
	m.fields = append(m.fields, m.namespaced(k), v)
	return nil
}

// OpenNamespace implements ObjectEncoder.
func (m *objectEncoder) OpenNamespace(k string) {
	if m.currNs == "" {
		m.currNs = k
	} else {
		m.currNs += "_" + k
	}
}

func (m *objectEncoder) namespaced(k string) string {
	if m.currNs == "" {
		return k
	}
	return m.currNs + "_" + k
}

// sliceArrayEncoder is an ArrayEncoder backed by a simple []interface{}.
type sliceArrayEncoder struct {
	elems []interface{}
}

func (s *sliceArrayEncoder) AppendArray(v zapcore.ArrayMarshaler) error {
	enc := &sliceArrayEncoder{}
	err := v.MarshalLogArray(enc)
	s.elems = append(s.elems, enc.elems)
	return err
}

func (s *sliceArrayEncoder) AppendObject(v zapcore.ObjectMarshaler) error {
	m := &objectEncoder{}
	err := v.MarshalLogObject(m)
	s.elems = append(s.elems, m.fields)
	return err
}

func (s *sliceArrayEncoder) AppendReflected(v interface{}) error {
	s.elems = append(s.elems, v)
	return nil
}

func (s *sliceArrayEncoder) AppendBool(v bool)              { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendByteString(v []byte)      { s.elems = append(s.elems, string(v)) }
func (s *sliceArrayEncoder) AppendComplex128(v complex128)  { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendComplex64(v complex64)    { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendDuration(v time.Duration) { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendFloat64(v float64)        { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendFloat32(v float32)        { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendInt(v int)                { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendInt64(v int64)            { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendInt32(v int32)            { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendInt16(v int16)            { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendInt8(v int8)              { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendString(v string)          { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendTime(v time.Time)         { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendUint(v uint)              { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendUint64(v uint64)          { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendUint32(v uint32)          { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendUint16(v uint16)          { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendUint8(v uint8)            { s.elems = append(s.elems, v) }
func (s *sliceArrayEncoder) AppendUintptr(v uintptr)        { s.elems = append(s.elems, v) }

type zapCore struct {
	logger *Logger

	modulePrefix string

	sync.Mutex
	encoder *objectEncoder
}

func newZapCore(logger log.Logger, module string, unwind int) *zapCore {
	log := &Logger{
		logger: log.WithPrefix(logger, "module", module, "caller", log.Caller(unwind)),
		module: module,
	}
	return &zapCore{
		logger:       log,
		modulePrefix: module + ":",
		encoder:      &objectEncoder{},
	}
}

// Implements zapcore.LevelEnabler.
func (l *zapCore) Enabled(level zapcore.Level) bool {
	switch level {
	case zapcore.DebugLevel:
		return l.logger.level <= LevelDebug
	case zapcore.InfoLevel:
		return l.logger.level <= LevelInfo
	case zapcore.WarnLevel:
		return l.logger.level <= LevelWarn
	case zapcore.ErrorLevel:
		return l.logger.level <= LevelError
	default:
		// DPanic, Panic, Fatal levels..
		return l.logger.level <= LevelError
	}
}

// Implements zapcore.Core.
func (l *zapCore) With(fields []zapcore.Field) zapcore.Core {
	l.Lock()
	defer l.Unlock()

	for _, field := range fields {
		field.AddTo(l.encoder)
	}
	l.logger = l.logger.With(l.encoder.fields...)

	return l
}

// Implements zapcore.Core.
func (l *zapCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !l.Enabled(e.Level) {
		return nil
	}
	return ce.AddCore(e, l)
}

// Implements zapcore.Core.
func (l *zapCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	encoder := &objectEncoder{}
	for _, field := range fields {
		field.AddTo(encoder)
	}

	keyvals := append([]interface{}{"msg", e.Message, "module", l.modulePrefix + e.LoggerName}, encoder.fields...)
	switch e.Level {
	case zapcore.DebugLevel:
		_ = level.Debug(l.logger.logger).Log(keyvals...)
	case zapcore.InfoLevel:
		_ = level.Info(l.logger.logger).Log(keyvals...)
	case zapcore.WarnLevel:
		_ = level.Warn(l.logger.logger).Log(keyvals...)
	default:
		_ = level.Error(l.logger.logger).Log(keyvals...)
	}
	return nil
}

// Implements zapcore.Core.
func (l *zapCore) Sync() error {
	return nil
}
