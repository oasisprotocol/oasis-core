// Package api implements the storage backend API.
package api

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
)

// KeySize is the size of a storage key in bytes.
const KeySize = 32

var (
	// ErrKeyNotFound is the error returned when the requested key
	// is not present in storage.
	ErrKeyNotFound = errors.New("storage: key not found")

	// ErrKeyExpired is the error returned when the requested key
	// is expired.
	ErrKeyExpired = errors.New("storage: key expired")

	// ErrIncoherentTime is the error returned when the timekeeping
	// is not coherent.
	ErrIncoherentTime = errors.New("storage: incoherent time")

	// ErrCantProve is the error returned when the backend is incapable
	// of generating proofs (unsupported, no key, etc).
	ErrCantProve = errors.New("storage: unable to provide proofs")

	// ReceiptSignatureContext is the signature context used for verifying receipts.
	ReceiptSignatureContext = []byte("EkStrRec")

	_ cbor.Marshaler   = (*Receipt)(nil)
	_ cbor.Unmarshaler = (*Receipt)(nil)
	_ cbor.Marshaler   = (*SignedReceipt)(nil)
	_ cbor.Unmarshaler = (*SignedReceipt)(nil)
)

// Key is a storage key.
type Key [KeySize]byte

// String returns a string representation of a key.
func (k Key) String() string {
	return hex.EncodeToString(k[:])
}

// KeyInfo is a key and it's associated metadata in storage.
type KeyInfo struct {
	// Key is the key of the value.
	Key Key

	// Expiration is the expiration time of the key/value pair.
	Expiration epochtime.EpochTime
}

// Value is a data blob and it's associated metadata in storage.
type Value struct {
	_struct struct{} `codec:",toarray"` // nolint

	// Data is the data blob.
	Data []byte

	// Expiration is the expiration time of the data blob.
	Expiration uint64
}

// String returns a string representation of a value.
func (v Value) String() string {
	return hex.EncodeToString(v.Data)
}

// Receipt is a proof that a set of keys exist in storage.
type Receipt struct {
	Keys []Key `codec:"keys"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (r *Receipt) MarshalCBOR() []byte {
	return cbor.Marshal(r)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (r *Receipt) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
}

// SignedReceipt is a signed proff that a set of keys exist in storage.
type SignedReceipt struct {
	signature.Signed
}

// Open first verifies the blob signature then unmarshals the blob.
func (s *SignedReceipt) Open(context []byte, receipt *Receipt) error {
	return s.Signed.Open(context, receipt)
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *SignedReceipt) MarshalCBOR() []byte {
	return s.Signed.MarshalCBOR()
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (s *SignedReceipt) UnmarshalCBOR(data []byte) error {
	return s.Signed.UnmarshalCBOR(data)
}

// InsertOptions specify the behavior of insert operations.
type InsertOptions struct {
	// LocalOnly specifies that certain backends which support combined
	// local/remote inserts (e.g., caching backends) should only insert
	// into the local cache and not propagate inserts remotely.
	LocalOnly bool
}

// Backend is a storage backend implementation.
type Backend interface {
	// Get returns the value for a specific immutable key.
	Get(context.Context, Key) ([]byte, error)

	// Fetch multiple values for specific immutable keys.
	GetBatch(context.Context, []Key) ([][]byte, error)

	// GetReceipt returns a signed proof that the specific keys are in
	// storage.
	GetReceipt(context.Context, []Key) (*SignedReceipt, error)

	// Insert inserts a specific value, which can later be retreived by
	// it's hash.  The expiration is the number of epochs for which the
	// value should remain available.
	Insert(context.Context, []byte, uint64, InsertOptions) error

	// InsertBatch inserts multiple values into storage. They can be later
	// retrieved by their hashes. The expiration is the number of epochs
	// for which the value should remain available.
	//
	// If the storage backend is unable to store any of the values, no
	// values will be stored.
	InsertBatch(context.Context, []Value, InsertOptions) error

	// GetKeys returns all of the keys in the storage database, along
	// with their associated metadata.
	GetKeys(context.Context) (<-chan *KeyInfo, error)

	// Cleanup closes/cleans up the storage backend.
	Cleanup()

	// Initialized returns a channel that will be closed when the
	// backend is initialized and ready to service requests.
	Initialized() <-chan struct{}
}

// HashStorageKey generates a storage key from it's value.
//
// All backends MUST use this method to hash values (generate keys).
func HashStorageKey(value []byte) Key {
	sum := sha512.Sum512_256(value)
	var k Key
	copy(k[:], sum[:])
	return k
}
