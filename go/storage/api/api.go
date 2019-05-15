// Package api implements the storage backend API.
package api

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
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

	// MKVSReceiptSignatureContext is the signature context used for verifying MKVS receipts.
	MKVSReceiptSignatureContext = []byte("EkStrRct")

	_ cbor.Marshaler   = (*Receipt)(nil)
	_ cbor.Unmarshaler = (*Receipt)(nil)
	_ cbor.Marshaler   = (*SignedReceipt)(nil)
	_ cbor.Unmarshaler = (*SignedReceipt)(nil)
	_ cbor.Marshaler   = (*MKVSReceiptBody)(nil)
	_ cbor.Unmarshaler = (*MKVSReceiptBody)(nil)
	_ cbor.Marshaler   = (*MKVSReceipt)(nil)
	_ cbor.Unmarshaler = (*MKVSReceipt)(nil)
)

// Key is a storage key.
type Key [KeySize]byte

// String returns a string representation of a key.
func (k Key) String() string {
	return hex.EncodeToString(k[:])
}

// KeyInfo is a key and its associated metadata in storage.
type KeyInfo struct {
	// Key is the key of the value.
	Key Key

	// Expiration is the expiration time of the key/value pair.
	Expiration epochtime.EpochTime
}

// Value is a data blob and its associated metadata in storage.
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

// SignedReceipt is a signed proof that a set of keys exist in storage.
type SignedReceipt struct {
	signature.Signed
}

// Open first verifies the blob signature then unmarshals the blob.
func (s *SignedReceipt) Open(receipt *Receipt) error {
	return s.Signed.Open(ReceiptSignatureContext, receipt)
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

// WriteLog is a write log.
//
// The keys in the write log must be unique.
type WriteLog = urkel.WriteLog

// LogEntry is a write log entry.
type LogEntry = urkel.LogEntry

// ReceiptBody is the body of a receipt.
type MKVSReceiptBody struct {
	// Version is the storage data structure version.
	Version uint16
	// Roots are the merkle roots of the merklized data structure that the
	// storage node is certifying to store.
	Roots []hash.Hash
}

// MKVSReceipt is a signed MKVSReceiptBody.
type MKVSReceipt struct {
	signature.Signed
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (rb *MKVSReceiptBody) MarshalCBOR() []byte {
	return cbor.Marshal(rb)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (rb *MKVSReceiptBody) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, rb)
}

// Open first verifies the blob signature then unmarshals the blob.
func (s *MKVSReceipt) Open(receipt *MKVSReceiptBody) error {
	return s.Signed.Open(MKVSReceiptSignatureContext, receipt)
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *MKVSReceipt) MarshalCBOR() []byte {
	return s.Signed.MarshalCBOR()
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (s *MKVSReceipt) UnmarshalCBOR(data []byte) error {
	return s.Signed.UnmarshalCBOR(data)
}

// NodeID is a root-relative node identifier which uniquely identifies
// a node under a given root.
type NodeID = urkel.NodeID

// Key is a node's key spelled out from the root to the node.
type MKVSKey = urkel.Key

// Node is either an InternalNode or a LeafNode.
type Node = urkel.Node

// Pointer is a pointer to another node.
type Pointer = urkel.Pointer

// InternalNode is an internal node with two children.
type InternalNode = urkel.InternalNode

// LeafNode is a leaf node containing a key/value pair.
type LeafNode = urkel.LeafNode

// MKVSValue holds the value.
type MKVSValue = urkel.Value

// SubtreeIndex is a subtree index.
type SubtreeIndex = syncer.SubtreeIndex

// InvalidSubtreeIndex is an invalid subtree index.
const InvalidSubtreeIndex = syncer.InvalidSubtreeIndex

// SubtreePointer is a pointer into the compressed representation of a
// subtree.
type SubtreePointer = syncer.SubtreePointer

// InternalNodeSummary is a compressed (index-only) representation of an
// internal node.
type InternalNodeSummary = syncer.InternalNodeSummary

// Subtree is a compressed representation of a subtree.
type Subtree = syncer.Subtree

// ApplyOp is an apply operation within a batch of apply operations.
type ApplyOp struct {
	// Root is the merkle root to apply the operations against. It may
	// refer to a nil node (empty hash) in which case a new root will be
	// created.
	Root hash.Hash
	// ExpectedNewRoot is the expected merkle root after applying the
	// write log.
	ExpectedNewRoot hash.Hash
	// WriteLog is a write log of operations to apply.
	WriteLog WriteLog
}

// Backend is a storage backend implementation.
type Backend interface {
	syncer.ReadSyncer

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

	// Apply applies a set of operations against the MKVS.  The root may refer
	// to a nil node, in which case a new root will be created.
	// The expected new root is used to check if the new root after all the
	// operations are applied already exists in the local DB.  If it does, the
	// Apply is ignored.
	Apply(context.Context, hash.Hash, hash.Hash, WriteLog) (*MKVSReceipt, error)

	// ApplyBatch applies multiple sets of operations against the MKVS and
	// returns a single receipt covering all applied roots.
	//
	// See Apply for more details.
	ApplyBatch(context.Context, []ApplyOp) (*MKVSReceipt, error)

	// Cleanup closes/cleans up the storage backend.
	Cleanup()

	// Initialized returns a channel that will be closed when the
	// backend is initialized and ready to service requests.
	Initialized() <-chan struct{}
}

// HashStorageKey generates a storage key from its value.
//
// All content addressable storage backends MUST use this method to hash values
// (generate keys).
func HashStorageKey(value []byte) Key {
	sum := sha512.Sum512_256(value)
	var k Key
	copy(k[:], sum[:])
	return k
}

// Genesis is the storage genesis state.
type Genesis struct {
	// State is the genesis state for the merklized key-value store.
	State WriteLog `codec:"state"`
}
