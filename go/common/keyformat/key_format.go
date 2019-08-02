package keyformat

import (
	"encoding"
	"encoding/binary"
	"fmt"
)

// KeyFormat is a key formatting helper to be used together with key-value
// backends for constructing keys.
type KeyFormat struct {
	// prefix is the one-byte key prefix that denotes the type of the key.
	prefix byte
	// layout is a list of bytes sizes of all elements in the key format.
	layout []int
	// size is the total size of the key in bytes.
	size int
}

// New constructs a new key format.
func New(prefix byte, layout ...interface{}) *KeyFormat {
	kf := &KeyFormat{
		prefix: prefix,
		layout: make([]int, len(layout)),
	}

	for i, item := range layout {
		size := kf.getSize(item)
		kf.layout[i] = size
		kf.size += size
	}

	return kf
}

// Size returns the size in bytes of the resulting key.
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
	if len(values) > len(k.layout) {
		panic("key format: number of values greater than layout")
	}

	size := 1
	for i := range values {
		size += k.layout[i]
	}
	result := make([]byte, size)

	result[0] = k.prefix
	offset := 1
	for i, v := range values {
		buf := result[offset : offset+k.layout[i]]
		offset += k.layout[i]

		switch t := v.(type) {
		case uint64:
			// Use big endian encoding so the keys sort correctly when doing
			// range queries.
			binary.BigEndian.PutUint64(buf, t)
		case *uint64:
			binary.BigEndian.PutUint64(buf, *t)
		case encoding.BinaryMarshaler:
			data, err := t.MarshalBinary()
			if err != nil {
				panic(fmt.Sprintf("key format: failed to marshal: %s", err))
			}

			copy(buf[:], data)
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

	if len(values) > len(k.layout) {
		panic("key format: number of values greater than layout")
	}
	if len(data) != k.Size() {
		panic("key format: malformed input")
	}

	offset := 1
	for i, v := range values {
		buf := data[offset : offset+k.layout[i]]
		offset += k.layout[i]

		switch t := v.(type) {
		case *uint64:
			// Use big endian encoding so the keys sort correctly when doing
			// range queries.
			*t = binary.BigEndian.Uint64(buf)
		case encoding.BinaryUnmarshaler:
			err := t.UnmarshalBinary(buf)
			if err != nil {
				panic(fmt.Sprintf("key format: failed to unmarshal: %s", err))
			}
		default:
			panic(fmt.Sprintf("unsupported type: %T", t))
		}
	}

	return true
}

func (k *KeyFormat) getSize(l interface{}) int {
	switch t := l.(type) {
	case uint64:
		return 8
	case *uint64:
		return 8
	case encoding.BinaryMarshaler:
		// Make sure that the type supports both marshalling and unmarshalling.
		_ = l.(encoding.BinaryUnmarshaler)

		data, _ := t.MarshalBinary()
		return len(data)
	default:
		panic(fmt.Sprintf("unsupported type: %T", l))
	}
}
