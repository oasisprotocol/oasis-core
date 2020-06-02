package keyformat

import (
	"encoding"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

// PreHashed represents a pre-hashed value that will be encoded without additional hashing when used
// together with a hashed format.
type PreHashed hash.Hash

// MarshalBinary encodes a hash into binary form.
func (ph *PreHashed) MarshalBinary() ([]byte, error) {
	return (*hash.Hash)(ph).MarshalBinary()
}

// UnmarshalBinary decodes a binary marshaled hash.
func (ph *PreHashed) UnmarshalBinary(data []byte) error {
	return (*hash.Hash)(ph).UnmarshalBinary(data)
}

// Equal compares vs another hash for equality.
func (ph *PreHashed) Equal(cmp *PreHashed) bool {
	return (*hash.Hash)(ph).Equal((*hash.Hash)(cmp))
}

// String returns the string representation of a hash.
func (ph PreHashed) String() string {
	return hash.Hash(ph).String()
}

type hashedFormat struct {
	inner interface{}
}

func (h *hashedFormat) getData(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case encoding.BinaryMarshaler:
		return t.MarshalBinary()
	case []byte:
		return t, nil
	default:
		return nil, fmt.Errorf("unsupported type: %T", t)
	}
}

// Implements CustomFormat.
func (h *hashedFormat) MarshalBinary(v interface{}) (data []byte, err error) {
	if ph, ok := v.(*PreHashed); ok {
		return ph[:], nil
	}

	data, err = h.getData(v)
	if err != nil {
		return
	}
	hh := hash.NewFromBytes(data)
	data = hh[:]
	return
}

// Implements CustomFormat.
func (h *hashedFormat) UnmarshalBinary(v interface{}, data []byte) error {
	if ph, ok := v.(*PreHashed); ok {
		return ph.UnmarshalBinary(data)
	}
	return fmt.Errorf("hashed format can only be decoded into a keyformat.PreHashed")
}

// Implements CustomFormat.
func (h *hashedFormat) Size() int {
	return hash.Size
}

// H wraps a key element to signal that the element should be hashed after regular encoding.
func H(inner interface{}) CustomFormat {
	return &hashedFormat{inner}
}
