// Package hash implements a cryptographic hash over arbitrary binary data.
package hash

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

// Size is the size of the cryptographic hash in bytes.
const Size = 32

var (
	// ErrMalformed is the error returned when a hash is malformed.
	ErrMalformed = errors.New("hash: malformed hash")
	// ErrTruncateSize is the error returned when trying to truncate a hash to an invalid size.
	ErrTruncateSize = errors.New("hash: invalid truncate size")

	emptyHash = sha512.Sum512_256([]byte{})

	_ encoding.BinaryMarshaler   = (*Hash)(nil)
	_ encoding.BinaryUnmarshaler = (*Hash)(nil)
)

// Hash is a cryptographic hash over arbitrary binary data.
type Hash [Size]byte

// MarshalBinary encodes a hash into binary form.
func (h *Hash) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, h[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled hash.
func (h *Hash) UnmarshalBinary(data []byte) error {
	if len(data) != Size {
		return ErrMalformed
	}

	copy(h[:], data)

	return nil
}

// MarshalText encodes a Hash into text form.
func (h Hash) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(h[:])), nil
}

// UnmarshalText decodes a text marshaled Hash.
func (h *Hash) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return h.UnmarshalBinary(b)
}

// UnmarshalHex deserializes a hexadecimal text string into the given type.
func (h *Hash) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return h.UnmarshalBinary(b)
}

// From sets the hash to that of an arbitrary CBOR serializeable interface.
func (h *Hash) From(v interface{}) {
	h.FromBytes(cbor.Marshal(v))
}

// FromBytes sets the hash to that of an arbitrary byte string.
func (h *Hash) FromBytes(data ...[]byte) {
	hasher := sha512.New512_256()
	for _, d := range data {
		_, _ = hasher.Write(d)
	}
	sum := hasher.Sum([]byte{})
	_ = h.UnmarshalBinary(sum[:])
}

// Equal compares vs another hash for equality.
func (h *Hash) Equal(cmp *Hash) bool {
	if cmp == nil {
		return false
	}
	return subtle.ConstantTimeCompare(h[:], cmp[:]) == 1
}

// Empty sets the hash to that of an empty (0 byte) string.
func (h *Hash) Empty() {
	copy(h[:], emptyHash[:])
}

// IsEmpty returns true iff the hash is that of an empty (0 byte) string.
func (h *Hash) IsEmpty() bool {
	return subtle.ConstantTimeCompare(h[:], emptyHash[:]) == 1
}

// String returns the string representation of a hash.
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// Truncate returns the first n bytes of a hash.
func (h Hash) Truncate(n int) ([]byte, error) {
	if n <= 0 || n > Size {
		return nil, ErrTruncateSize
	}
	return append([]byte{}, h[:n]...), nil
}

// NewFrom creates a new hash by hashing the CBOR representation of the given type.
func NewFrom(v interface{}) (h Hash) {
	h.From(v)
	return
}

// NewFromBytes creates a new hash by hashing the provided byte string(s).
func NewFromBytes(data ...[]byte) (h Hash) {
	h.FromBytes(data...)
	return
}

// Builder is a hash builder that can be used to compute hashes iteratively.
type Builder struct {
	hasher hash.Hash
}

// Write adds more data to the running hash.
// It never returns an error.
func (b *Builder) Write(p []byte) (int, error) {
	return b.hasher.Write(p)
}

// Build returns the current hash.
// It does not change the underlying hash state.
func (b *Builder) Build() (h Hash) {
	sum := b.hasher.Sum([]byte{})
	_ = h.UnmarshalBinary(sum[:])
	return
}

// NewBuilder creates a new hash builder.
func NewBuilder() *Builder {
	return &Builder{hasher: sha512.New512_256()}
}
