package logging

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/multierr"
	"go.uber.org/zap/zapcore"
)

// Tests are based on: https://github.com/uber-go/zap/blob/master/zapcore/memory_encoder_test.go

// maybeNamespace is an ObjectMarshaler that sometimes opens a namespace
type maybeNamespace struct{ bool }

func (m maybeNamespace) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("obj-out", "obj-outside-namespace")
	if m.bool {
		enc.OpenNamespace("obj-namespace")
		enc.AddString("obj-in", "obj-inside-namespace")
	}
	return nil
}

// Nested Array- and ObjectMarshalers.
type turducken struct{}

func (t turducken) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return enc.AddArray("ducks", zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
		for i := 0; i < 2; i++ {
			if err := arr.AppendObject(zapcore.ObjectMarshalerFunc(func(inner zapcore.ObjectEncoder) error {
				inner.AddString("in", "chicken")
				return nil
			})); err != nil {
				return err
			}
		}
		return nil
	}))
}

type turduckens int

func (t turduckens) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	var err error
	tur := turducken{}
	for i := 0; i < int(t); i++ {
		err = multierr.Append(err, enc.AppendObject(tur))
	}
	return err
}

func TestObjectEncoder(t *testing.T) {
	// Ensure our custom encoder encodes all types as expected.

	expectedTur := []interface{}{
		"ducks",
		[]interface{}{
			[]interface{}{"in", "chicken"},
			[]interface{}{"in", "chicken"},
		},
	}
	tests := []struct {
		desc     string
		f        func(zapcore.ObjectEncoder)
		expected interface{}
	}{
		{
			desc: "AddArray",
			f: func(e zapcore.ObjectEncoder) {
				assert.NoError(t, e.AddArray("k", zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
					arr.AppendBool(true)
					arr.AppendBool(false)
					arr.AppendBool(true)
					return nil
				})), "Expected AddArray to succeed.")
			},
			expected: []interface{}{"k", []interface{}{true, false, true}},
		},
		{
			desc: "AddArray (nested)",
			f: func(e zapcore.ObjectEncoder) {
				assert.NoError(t, e.AddArray("k", turduckens(2)), "Expected AddArray to succeed.")
			},
			expected: []interface{}{"k", []interface{}{expectedTur, expectedTur}},
		},
		{
			desc: "AddArray (empty)",
			f: func(e zapcore.ObjectEncoder) {
				assert.NoError(t, e.AddArray("k", turduckens(0)), "Expected AddArray to succeed.")
			},
			expected: []interface{}{"k", []interface{}{}},
		},
		{
			desc:     "AddBinary",
			f:        func(e zapcore.ObjectEncoder) { e.AddBinary("k", []byte("foo")) },
			expected: []interface{}{"k", []byte("foo")},
		},
		{
			desc:     "AddByteString",
			f:        func(e zapcore.ObjectEncoder) { e.AddByteString("k", []byte("foo")) },
			expected: []interface{}{"k", "foo"},
		},
		{
			desc:     "AddBool",
			f:        func(e zapcore.ObjectEncoder) { e.AddBool("k", true) },
			expected: []interface{}{"k", true},
		},
		{
			desc:     "AddComplex128",
			f:        func(e zapcore.ObjectEncoder) { e.AddComplex128("k", 1+2i) },
			expected: []interface{}{"k", 1 + 2i},
		},
		{
			desc:     "AddComplex64",
			f:        func(e zapcore.ObjectEncoder) { e.AddComplex64("k", 1+2i) },
			expected: []interface{}{"k", complex64(1 + 2i)},
		},
		{
			desc:     "AddDuration",
			f:        func(e zapcore.ObjectEncoder) { e.AddDuration("k", time.Millisecond) },
			expected: []interface{}{"k", time.Millisecond},
		},
		{
			desc:     "AddFloat64",
			f:        func(e zapcore.ObjectEncoder) { e.AddFloat64("k", 3.14) },
			expected: []interface{}{"k", 3.14},
		},
		{
			desc:     "AddFloat32",
			f:        func(e zapcore.ObjectEncoder) { e.AddFloat32("k", 3.14) },
			expected: []interface{}{"k", float32(3.14)},
		},
		{
			desc:     "AddInt",
			f:        func(e zapcore.ObjectEncoder) { e.AddInt("k", 42) },
			expected: []interface{}{"k", 42},
		},

		{
			desc:     "AddInt64",
			f:        func(e zapcore.ObjectEncoder) { e.AddInt64("k", 42) },
			expected: []interface{}{"k", int64(42)},
		},
		{
			desc:     "AddInt32",
			f:        func(e zapcore.ObjectEncoder) { e.AddInt32("k", 42) },
			expected: []interface{}{"k", int32(42)},
		},

		{
			desc:     "AddInt16",
			f:        func(e zapcore.ObjectEncoder) { e.AddInt16("k", 42) },
			expected: []interface{}{"k", int16(42)},
		},
		{
			desc:     "AddInt8",
			f:        func(e zapcore.ObjectEncoder) { e.AddInt8("k", 42) },
			expected: []interface{}{"k", int8(42)},
		},

		{
			desc:     "AddString",
			f:        func(e zapcore.ObjectEncoder) { e.AddString("k", "v") },
			expected: []interface{}{"k", "v"},
		},
		{
			desc:     "AddTime",
			f:        func(e zapcore.ObjectEncoder) { e.AddTime("k", time.Unix(0, 100)) },
			expected: []interface{}{"k", time.Unix(0, 100)},
		},
		{
			desc:     "AddUint",
			f:        func(e zapcore.ObjectEncoder) { e.AddUint("k", 42) },
			expected: []interface{}{"k", uint(42)},
		},
		{
			desc:     "AddUint64",
			f:        func(e zapcore.ObjectEncoder) { e.AddUint64("k", 42) },
			expected: []interface{}{"k", uint64(42)},
		},
		{
			desc:     "AddUint32",
			f:        func(e zapcore.ObjectEncoder) { e.AddUint32("k", 42) },
			expected: []interface{}{"k", uint32(42)},
		},
		{
			desc:     "AddUint16",
			f:        func(e zapcore.ObjectEncoder) { e.AddUint16("k", 42) },
			expected: []interface{}{"k", uint16(42)},
		},
		{
			desc:     "AddUint8",
			f:        func(e zapcore.ObjectEncoder) { e.AddUint8("k", 42) },
			expected: []interface{}{"k", uint8(42)},
		},
		{
			desc:     "AddUintptr",
			f:        func(e zapcore.ObjectEncoder) { e.AddUintptr("k", 42) },
			expected: []interface{}{"k", uintptr(42)},
		},
		{
			desc: "AddReflected",
			f: func(e zapcore.ObjectEncoder) {
				assert.NoError(t, e.AddReflected("k", map[string]interface{}{"foo": 5}), "Expected AddReflected to succeed.")
			},
			expected: []interface{}{"k", map[string]interface{}{"foo": 5}},
		},
		{
			desc: "OpenNamespace",
			f: func(e zapcore.ObjectEncoder) {
				e.OpenNamespace("k")
				e.AddInt("foo", 1)
				e.OpenNamespace("middle")
				e.AddInt("foo", 2)
				e.OpenNamespace("inner")
				e.AddInt("foo", 3)
			},
			expected: []interface{}{"k_foo", 1, "k_middle_foo", 2, "k_middle_inner_foo", 3},
		},
		{
			desc: "object (no nested namespace) then string",
			f: func(e zapcore.ObjectEncoder) {
				e.OpenNamespace("k")
				_ = e.AddObject("obj", maybeNamespace{false})
				e.AddString("not-obj", "should-be-outside-obj")
			},
			expected: []interface{}{"k_obj", []interface{}{"obj-out", "obj-outside-namespace"}, "k_not-obj", "should-be-outside-obj"},
		},
		{
			desc: "object (with nested namespace) then string",
			f: func(e zapcore.ObjectEncoder) {
				e.OpenNamespace("k")
				_ = e.AddObject("obj", maybeNamespace{true})
				e.AddString("not-obj", "should-be-outside-obj")
			},
			expected: []interface{}{"k_obj", []interface{}{"obj-out", "obj-outside-namespace", "obj-namespace_obj-in", "obj-inside-namespace"}, "k_not-obj", "should-be-outside-obj"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			enc := &objectEncoder{}
			tt.f(enc)
			assert.Equal(t, tt.expected, enc.fields, "Unexpected encoder output.")
		})
	}
}
