package keyformat

import (
	"encoding"
	"encoding/binary"
	"fmt"
)

// CustomFormat specifies a custom encoding format for a key element.
type CustomFormat interface {
	// Size returns the size of the encoded element.
	Size() int

	// MarshalBinary encodes the passed value into its binary representation.
	MarshalBinary(v interface{}) ([]byte, error)

	// UnmarshalBinary decodes the passed value from its binary representation.
	UnmarshalBinary(v interface{}, data []byte) error
}

type elementMeta struct {
	size   int
	custom CustomFormat
}

func (m *elementMeta) checkSize(index, size int) {
	if m.size != size {
		panic(fmt.Sprintf("key format: incompatible element %d (size: %d expected: %d)",
			index,
			size,
			m.size,
		))
	}
}

// KeyFormat is a key formatting helper to be used together with key-value
// backends for constructing keys.
type KeyFormat struct {
	// prefix is the one-byte key prefix that denotes the type of the key.
	prefix byte
	// meta is a list of key format element metadata.
	meta []*elementMeta
	// size is the total size of the key in bytes.
	size int
}

// New constructs a new key format.
func New(prefix byte, layout ...interface{}) *KeyFormat {
	kf := &KeyFormat{
		prefix: prefix,
		meta:   make([]*elementMeta, len(layout)),
	}

	hasVarSize := false
	for i, item := range layout {
		meta := kf.getElementMeta(item)
		if meta.size == -1 {
			if hasVarSize {
				panic("key format: there can be only one variable-sized element")
			}
			hasVarSize = true
		} else {
			kf.size += meta.size
		}

		kf.meta[i] = meta
	}

	return kf
}

// Size returns the minimum size in bytes of the resulting key.
func (k *KeyFormat) Size() int {
	return 1 + k.size
}

// Encode encodes values into a key.
//
// You can pass either the same amount of values as specified in the layout
// or less. In case less values are specified this will generate a shorter
// key containing only the specified values.
//
// In case no values are specified this will only output the key prefix.
func (k *KeyFormat) Encode(values ...interface{}) []byte {
	if len(values) > len(k.meta) {
		panic("key format: number of values greater than layout")
	}

	size := 1
	for i := range values {
		meta := k.meta[i]
		elemLen := meta.size
		if elemLen == -1 {
			// Variable-sized element, the passed value must be a []byte.
			elemLen = len(values[i].([]byte))
		}

		size += elemLen
	}
	result := make([]byte, size)

	result[0] = k.prefix
	offset := 1
	for i, v := range values {
		meta := k.meta[i]
		elemLen := meta.size
		if elemLen == -1 {
			// Variable-sized element, the passed value must be a []byte (was checked above).
			elemLen = len(v.([]byte))
		}
		buf := result[offset : offset+elemLen]
		offset += elemLen

		switch t := v.(type) {
		case uint8:
			meta.checkSize(i, 1)
			buf[0] = t
		case *uint8:
			meta.checkSize(i, 1)
			buf[0] = *t
		case uint32:
			// Use big endian encoding so the keys sort correctly when doing
			// range queries.
			meta.checkSize(i, 4)
			binary.BigEndian.PutUint32(buf, t)
		case *uint32:
			meta.checkSize(i, 4)
			binary.BigEndian.PutUint32(buf, *t)
		case uint64:
			meta.checkSize(i, 8)
			binary.BigEndian.PutUint64(buf, t)
		case *uint64:
			meta.checkSize(i, 8)
			binary.BigEndian.PutUint64(buf, *t)
		case int64:
			meta.checkSize(i, 8)
			binary.BigEndian.PutUint64(buf, uint64(t))
		case *int64:
			meta.checkSize(i, 8)
			binary.BigEndian.PutUint64(buf, uint64(*t))
		case encoding.BinaryMarshaler:
			var (
				data []byte
				err  error
			)
			if meta.custom != nil {
				data, err = meta.custom.MarshalBinary(t)
			} else {
				data, err = t.MarshalBinary()
			}
			if err != nil {
				panic(fmt.Sprintf("key format: failed to marshal element %d: %s", i, err))
			}
			if len(data) != meta.size {
				panic(fmt.Sprintf("key format: unexpected marshalled size %d for element %d", len(data), i))
			}

			copy(buf[:], data)
		case []byte:
			if meta.custom != nil {
				var err error
				t, err = meta.custom.MarshalBinary(t)
				if err != nil {
					panic(fmt.Sprintf("key format: failed to marshal element %d: %s", i, err))
				}
			}
			copy(buf[:], t)
		default:
			panic(fmt.Sprintf("unsupported type: %T", t))
		}
	}

	return result
}

// Decode decodes a key into its individual values.
//
// Returns false and doesn't modify the passed values if the key prefix
// doesn't match.
func (k *KeyFormat) Decode(data []byte, values ...interface{}) bool {
	if data[0] != k.prefix {
		return false
	}

	if len(values) > len(k.meta) {
		panic("key format: number of values greater than layout")
	}
	if len(data) < k.Size() {
		panic("key format: malformed input")
	}

	offset := 1
	for i, v := range values {
		meta := k.meta[i]
		elemLen := meta.size
		if elemLen == -1 {
			// Variable-sized element, compute its size.
			elemLen = len(data) - k.Size()
		}
		buf := data[offset : offset+elemLen]
		offset += elemLen

		switch t := v.(type) {
		case *uint8:
			meta.checkSize(i, 1)
			*t = buf[0]
		case *uint32:
			// Use big endian encoding so the keys sort correctly when doing
			// range queries.
			meta.checkSize(i, 4)
			*t = binary.BigEndian.Uint32(buf)
		case *uint64:
			meta.checkSize(i, 8)
			*t = binary.BigEndian.Uint64(buf)
		case *int64:
			meta.checkSize(i, 8)
			*t = int64(binary.BigEndian.Uint64(buf))
		case encoding.BinaryUnmarshaler:
			var err error
			if meta.custom != nil {
				err = meta.custom.UnmarshalBinary(t, buf)
			} else {
				err = t.UnmarshalBinary(buf)
			}
			if err != nil {
				panic(fmt.Sprintf("key format: failed to unmarshal: %s", err))
			}
		case *[]byte:
			if meta.custom != nil {
				if err := meta.custom.UnmarshalBinary(t, buf); err != nil {
					panic(fmt.Sprintf("key format: failed to unmarshal: %s", err))
				}
			} else {
				meta.checkSize(i, -1)
			}
			*t = make([]byte, elemLen)
			copy(*t, buf)
		default:
			panic(fmt.Sprintf("unsupported type: %T", t))
		}
	}

	return true
}

func (k *KeyFormat) getElementMeta(l interface{}) *elementMeta {
	switch t := l.(type) {
	case uint8:
		return &elementMeta{size: 1}
	case *uint8:
		return &elementMeta{size: 1}
	case uint32:
		return &elementMeta{size: 4}
	case *uint32:
		return &elementMeta{size: 4}
	case uint64:
		return &elementMeta{size: 8}
	case *uint64:
		return &elementMeta{size: 8}
	case int64:
		return &elementMeta{size: 8}
	case *int64:
		return &elementMeta{size: 8}
	case CustomFormat:
		return &elementMeta{size: t.Size(), custom: t}
	case encoding.BinaryMarshaler:
		data, _ := t.MarshalBinary()
		return &elementMeta{size: len(data)}
	case []byte:
		// A variable-size element -- there can be only one such element
		// in the whole key and during decoding its size is derived from
		// the key length and the sizes of other elements.
		return &elementMeta{size: -1}
	default:
		panic(fmt.Sprintf("unsupported type: %T", l))
	}
}
