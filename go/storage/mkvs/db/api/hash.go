package api

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

var (
	_ encoding.BinaryMarshaler   = (*TypedHash)(nil)
	_ encoding.BinaryUnmarshaler = (*TypedHash)(nil)
)

// TypedHashSize is the size of the TypedHash.
const TypedHashSize = hash.Size + 1

// TypedHash is a node hash prefixed with its root type.
type TypedHash [TypedHashSize]byte

// MarshalBinary encodes a typed hash into binary form.
func (h *TypedHash) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, h[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled hash.
func (h *TypedHash) UnmarshalBinary(data []byte) error {
	if len(data) != TypedHashSize {
		fmt.Printf("\nunexpected typedhash size: got %v, expected %v\n", len(data), TypedHashSize)
		return hash.ErrMalformed
	}

	copy(h[:], data)

	return nil
}

// MarshalText encodes a Hash into text form.
func (h TypedHash) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(h[:])), nil
}

// UnmarshalText decodes a text marshaled Hash.
func (h *TypedHash) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return h.UnmarshalBinary(b)
}

// UnmarshalHex deserializes a hexadecimal text string into the given type.
func (h *TypedHash) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return h.UnmarshalBinary(b)
}

// Equal compares vs another hash for equality.
func (h *TypedHash) Equal(cmp *TypedHash) bool {
	if cmp == nil {
		return false
	}
	return bytes.Equal(h[:], cmp[:])
}

// String returns the string representation of a typed hash.
func (h TypedHash) String() string {
	return fmt.Sprintf("%v:%s", node.RootType(h[0]), hex.EncodeToString(h[1:]))
}

// FromParts returns the typed hash composed of the given type and hash.
func (h *TypedHash) FromParts(typ node.RootType, hash hash.Hash) {
	h[0] = byte(typ)
	copy(h[1:], hash[:])
}

// Type returns the storage type of the root corresponding to this typed hash.
func (h *TypedHash) Type() node.RootType {
	return node.RootType(h[0])
}

// Hash returns the hash portion of the typed hash.
func (h *TypedHash) Hash() (rh hash.Hash) {
	copy(rh[:], h[1:])
	return
}

// TypedHashFromParts creates a new typed hash with the parts given.
func TypedHashFromParts(typ node.RootType, hash hash.Hash) (h TypedHash) {
	h[0] = byte(typ)
	copy(h[1:], hash[:])
	return
}

// TypedHashFromRoot creates a new typed hash corresponding to the given storage root.
func TypedHashFromRoot(root node.Root) (h TypedHash) {
	h[0] = byte(root.Type)
	copy(h[1:], root.Hash[:])
	return
}
