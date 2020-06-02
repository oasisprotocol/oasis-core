package common

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

const (
	// NamespaceSize is the size of a chain namespace identifier in bytes.
	NamespaceSize = 32

	// NamespaceIDSize is the size of the identifier component of a namespace.
	NamespaceIDSize = NamespaceSize - 8

	NamespaceTest       NamespaceFlag = 1 << 63
	NamespaceKeyManager NamespaceFlag = 1 << 62

	flagsReserved = ^(NamespaceTest | NamespaceKeyManager)
)

var (
	// ErrMalformedNamespace is the error returned when a namespace
	// identifier is malformed.
	ErrMalformedNamespace = errors.New("malformed namespace")

	_ encoding.BinaryMarshaler   = (*Namespace)(nil)
	_ encoding.BinaryUnmarshaler = (*Namespace)(nil)
)

// NamespaceFlag is a namespace flag.
type NamespaceFlag uint64

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
	if !n.isValid() {
		return ErrMalformedNamespace
	}

	return nil
}

// MarshalText encodes a namespace identifier into text form.
func (n Namespace) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(n[:])), nil
}

// UnmarshalText decodes a text marshaled namespace identifier.
func (n *Namespace) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return n.UnmarshalBinary(b)
}

// UnmarshalHex deserializes a hexadecimal text string into the given type.
func (n *Namespace) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return n.UnmarshalBinary(b)
}

// Equal compares vs another namespace for equality.
func (n *Namespace) Equal(cmp *Namespace) bool {
	if cmp == nil {
		return false
	}
	return bytes.Equal(n[:], cmp[:])
}

// String returns the string representation of a chain namespace identifier.
func (n Namespace) String() string {
	return hex.EncodeToString(n[:])
}

// IsTest returns true iff the namespace is for a test runtime.
func (n Namespace) IsTest() bool {
	return n.flags()&NamespaceTest != 0
}

// IsKeyManager returns true iff the namespace is for a key manager runtime.
func (n Namespace) IsKeyManager() bool {
	return n.flags()&NamespaceKeyManager != 0
}

func (n Namespace) isValid() bool {
	return n.flags()&flagsReserved == 0
}

func (n Namespace) flags() NamespaceFlag {
	return NamespaceFlag(binary.BigEndian.Uint64(n[0:8]))
}

// NewNamespace returns a new namespace from it's component ID and flags.
func NewNamespace(id [NamespaceIDSize]byte, flags NamespaceFlag) (Namespace, error) {
	var n Namespace

	binary.BigEndian.PutUint64(n[0:8], uint64(flags))
	copy(n[8:], id[:])
	if !n.isValid() {
		return n, ErrMalformedNamespace
	}

	return n, nil
}

// NewTestNamespaceFromSeed returns a test namespace from a seed and flags.
func NewTestNamespaceFromSeed(seed []byte, flags NamespaceFlag) Namespace {
	h := hash.NewFromBytes(seed)

	var rtID [NamespaceIDSize]byte
	copy(rtID[:], h[:])

	ns, _ := NewNamespace(rtID, NamespaceTest|flags)
	return ns
}
