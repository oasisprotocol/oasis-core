package badger

import (
	"crypto/subtle"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

var (
	_ encoding.BinaryMarshaler   = (*typedHash)(nil)
	_ encoding.BinaryUnmarshaler = (*typedHash)(nil)
)

const typedHashSize = hash.Size + 1

// typedHash is a node hash prefixed with its root type.
type typedHash [typedHashSize]byte

// MarshalBinary encodes a typed hash into binary form.
func (h *typedHash) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, h[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled hash.
func (h *typedHash) UnmarshalBinary(data []byte) error {
	if len(data) != typedHashSize {
		return hash.ErrMalformed
	}

	copy(h[:], data)

	return nil
}

// MarshalText encodes a Hash into text form.
func (h typedHash) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(h[:])), nil
}

// UnmarshalText decodes a text marshaled Hash.
func (h *typedHash) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return h.UnmarshalBinary(b)
}

// UnmarshalHex deserializes a hexadecimal text string into the given type.
func (h *typedHash) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return h.UnmarshalBinary(b)
}

// Equal compares vs another hash for equality.
func (h *typedHash) Equal(cmp *typedHash) bool {
	if cmp == nil {
		return false
	}
	return subtle.ConstantTimeCompare(h[:], cmp[:]) == 1
}

// String returns the string representation of a typed hash.
func (h typedHash) String() string {
	return fmt.Sprintf("%v:%s", node.RootType(h[0]), hex.EncodeToString(h[1:]))
}

// FromParts returns the typed hash composed of the given type and hash.
func (h *typedHash) FromParts(typ node.RootType, hash hash.Hash) {
	h[0] = byte(typ)
	copy(h[1:], hash[:])
}

// Type returns the storage type of the root corresponding to this typed hash.
func (h *typedHash) Type() node.RootType {
	return node.RootType(h[0])
}

// Hash returns the hash portion of the typed hash.
func (h *typedHash) Hash() (rh hash.Hash) {
	copy(rh[:], h[1:])
	return
}

// typedHashFromParts creates a new typed hash with the parts given.
func typedHashFromParts(typ node.RootType, hash hash.Hash) (h typedHash) {
	h[0] = byte(typ)
	copy(h[1:], hash[:])
	return
}

// typedHashFromRoot creates a new typed hash corresponding to the given storage root.
func typedHashFromRoot(root node.Root) (h typedHash) {
	h[0] = byte(root.Type)
	copy(h[1:], root.Hash[:])
	return
}
