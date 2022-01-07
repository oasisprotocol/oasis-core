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

	// NamespaceHexSize is the size of the chain namespace identifier in string format.
	NamespaceHexSize = NamespaceSize * 2

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
func (n Namespace) MarshalText() ([]byte, error) {
	return n.MarshalHex()
}

// UnmarshalText decodes a text marshaled namespace identifier.
func (n *Namespace) UnmarshalText(text []byte) error {
	err := n.UnmarshalHex(string(text))
	if err != nil {
		// For backwards compatibility (e.g. to be able to load the
		// Cobalt Upgrade genesis file), fallback to accepting
		// Base64-encoded namespace identifiers.
		return n.UnmarshalBase64(text)
	}
	return nil
}

// MarshalHex encodes a namespace identifier into a hexadecimal form.
func (n *Namespace) MarshalHex() ([]byte, error) {
	return []byte(hex.EncodeToString(n[:])), nil
}

// UnmarshalHex deserializes a hexadecimal text string into the given type.
func (n *Namespace) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return n.UnmarshalBinary(b)
}

// UnmarshalBase64 deserializes a Base64 text string into the given type.
func (n *Namespace) UnmarshalBase64(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
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

// Base64 returns the base64 string representation of a namespace identifier.
func (n Namespace) Base64() string {
	return base64.StdEncoding.EncodeToString(n[:])
}

// Hex returns the hexadecimal string representation of a namespace identifier.
func (n Namespace) Hex() string {
	return hex.EncodeToString(n[:])
}

// String returns the string representation of a namespace identifier.
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
