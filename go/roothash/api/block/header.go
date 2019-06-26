package block

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

const (
	// NamespaceSize is the size of a chain namespace identifier in bytes.
	NamespaceSize = 32
)

var (
	// ErrInvalidVersion is the error returned when a version is invalid.
	ErrInvalidVersion = errors.New("roothash: invalid version")

	// ErrMalformedNamespace is the error returned when a namespace
	// identifier is malformed.
	ErrMalformedNamespace = errors.New("roothash: malformed namespace")

	// IoKeyInputs is the key holding inputs in the I/O tree.
	IoKeyInputs = []byte("i")
	// IoKeyOutputs is the key holding outputs in the I/O tree.
	IoKeyOutputs = []byte("o")
	// IoKeyTags is the key holding tags in the I/O tree.
	IoKeyTags = []byte("t")

	_ encoding.BinaryMarshaler   = (*Namespace)(nil)
	_ encoding.BinaryUnmarshaler = (*Namespace)(nil)
	_ cbor.Marshaler             = (*Header)(nil)
	_ cbor.Unmarshaler           = (*Header)(nil)
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

// String returns the string representation of a chain namespace identifier.
func (n *Namespace) String() string {
	return hex.EncodeToString(n[:])
}

// HeaderType is the type of header.
type HeaderType uint8

const (
	// Normal is a normal header.
	Normal HeaderType = 0

	// RoundFailed is a header resulting from a failed round. Such a
	// header contains no transactions but advances the round as normal
	// to prevent replays of old commitments.
	RoundFailed HeaderType = 1

	// EpochTransition is a header resulting from an epoch transition.
	// Such a header contains no transactions but advances the round as
	// normal.
	EpochTransition HeaderType = 2
)

// Header is a block header.
//
// Keep this in sync with /runtime/src/common/roothash.rs.
type Header struct { // nolint: maligned
	// Version is the protocol version number.
	Version uint16 `codec:"version"`

	// Namespace is the header's chain namespace.
	Namespace Namespace `codec:"namespace"`

	// Round is the block round.
	Round uint64 `codec:"round"`

	// Timestamp is the block timestamp (POSIX time).
	Timestamp uint64 `codec:"timestamp"`

	// HeaderType is the header type.
	HeaderType HeaderType `codec:"header_type"`

	// PreviousHash is the previous block hash.
	PreviousHash hash.Hash `codec:"previous_hash"`

	// IORoot is the I/O merkle root.
	IORoot hash.Hash `codec:"io_root"`

	// StateRoot is the state merkle root.
	StateRoot hash.Hash `codec:"state_root"`

	// StorageSignatures are the storage receipt signatures for the merkle
	// roots.
	StorageSignatures []signature.Signature `codec:"storage_signatures"`
}

// IsParentOf returns true iff the header is the parent of a child header.
func (h *Header) IsParentOf(child *Header) bool {
	childHash := child.EncodedHash()
	return h.PreviousHash.Equal(&childHash)
}

// MostlyEqual compares vs another header for equality, omitting the
// StorageSignatures field as it is not universally guaranteed to be present.
//
// Locations where this matter should do the comparison manually.
func (h *Header) MostlyEqual(cmp *Header) bool {
	a, b := *h, *cmp
	a.StorageSignatures, b.StorageSignatures = []signature.Signature{}, []signature.Signature{}
	aHash, bHash := a.EncodedHash(), b.EncodedHash()
	return aHash.Equal(&bHash)
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (h *Header) MarshalCBOR() []byte {
	return cbor.Marshal(h)
}

// UnmarshalCBOR decodes a CBOR marshaled header.
func (h *Header) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, h)
}

// EncodedHash returns the encoded cryptographic hash of the header.
func (h *Header) EncodedHash() hash.Hash {
	var hh hash.Hash

	hh.From(h)

	return hh
}

// RootsForStorageReceipt gets the merkle roots that must be part of
// a storage receipt.
func (h *Header) RootsForStorageReceipt() []hash.Hash {
	return []hash.Hash{
		h.IORoot,
		h.StateRoot,
	}
}

// VerifyStorageReceiptSignatures validates that the storage receipt signatures
// match the signatures for the current merkle roots.
//
// Note: Ensuring that the signatures are signed by keypair(s) that are
// expected is the responsibility of the caller.
//
// TODO: After we switch to https://github.com/oasislabs/ed25519, use batch
// verification. This should be implemented as part of:
// https://github.com/oasislabs/ekiden/issues/1351.
func (h *Header) VerifyStorageReceiptSignatures() error {
	receiptBody := storage.ReceiptBody{
		Version: 1,
		Roots:   h.RootsForStorageReceipt(),
	}
	receipt := storage.Receipt{}
	receipt.Signed.Blob = receiptBody.MarshalCBOR()
	for _, sig := range h.StorageSignatures {
		receipt.Signed.Signature = sig
		var tmp storage.ReceiptBody
		if err := receipt.Open(&tmp); err != nil {
			return err
		}
	}
	return nil
}

// VerifyStorageReceipt validates that the provided storage receipt
// matches the header.
func (h *Header) VerifyStorageReceipt(receipt *storage.ReceiptBody) error {
	roots := h.RootsForStorageReceipt()
	if len(receipt.Roots) != len(roots) {
		return errors.New("roothash: receipt has unexpected number of roots")
	}

	for idx, v := range roots {
		if !bytes.Equal(v[:], receipt.Roots[idx][:]) {
			return errors.New("roothash: receipt has unexpected roots")
		}
	}

	return nil
}
