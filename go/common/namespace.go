package common

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"errors"
)

const (
	// NamespaceSize is the size of a chain namespace identifier in bytes.
	NamespaceSize = 32
)

var (
	// ErrMalformedNamespace is the error returned when a namespace
	// identifier is malformed.
	ErrMalformedNamespace = errors.New("malformed namespace")

	_ encoding.BinaryMarshaler   = (*Namespace)(nil)
	_ encoding.BinaryUnmarshaler = (*Namespace)(nil)
)

// Namespace is a chain namespace identifier.
type Namespace [NamespaceSize]byte

// MarshalBinary encodes a namespace identifier into binary form.
func (n *Namespace) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, n[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled namespace identifier.
func (n *Namespace) UnmarshalBinary(data []byte) error {
	if len(data) != NamespaceSize {
		return ErrMalformedNamespace
	}

	copy(n[:], data)

	return nil
}

// Equal compares vs another namespace for equality.
func (n *Namespace) Equal(cmp *Namespace) bool {
	if cmp == nil {
		return false
	}
	return bytes.Equal(n[:], cmp[:])
}

// String returns the string representation of a chain namespace identifier.
func (n *Namespace) String() string {
	return hex.EncodeToString(n[:])
}
