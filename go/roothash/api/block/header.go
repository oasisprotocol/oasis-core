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

	// GroupHash is the computation group hash.
	GroupHash hash.Hash `codec:"group_hash"`

	// IORoot is the I/O merkle root.
	IORoot hash.Hash `codec:"io_root"`

	// StateRoot is the state merkle root.
	StateRoot hash.Hash `codec:"state_root"`

	// CommitmentsHash is the Commitments hash.
	CommitmentsHash hash.Hash `codec:"commitments_hash"`

	// StorageReceipt is the storage receipt for the hashes.
	StorageReceipt signature.Signature `codec:"storage_receipt"`
}

// IsParentOf returns true iff the header is the parent of a child header.
func (h *Header) IsParentOf(child *Header) bool {
	childHash := child.EncodedHash()
	return h.PreviousHash.Equal(&childHash)
}

// MostlyEqual compares vs another header for equality, omitting the
// StorageReceipt field as it is not universally guaranteed to be present.
//
// Locations where this matter should do the comparison manually.
func (h *Header) MostlyEqual(cmp *Header) bool {
	a, b := *h, *cmp
	a.StorageReceipt, b.StorageReceipt = signature.Signature{}, signature.Signature{}
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

// VerifyStorageReceiptSignature validates that the storage receipt
// signature matches the hashes.
//
// Note: Ensuring that the signature is signed by the keypair that is
// expected is the responsibility of the caller.
func (h *Header) VerifyStorageReceiptSignature() error {
	receipt := storage.MKVSReceiptBody{
		Version: 1,
		Roots:   h.RootsForStorageReceipt(),
	}

	signed := signature.Signed{
		Blob:      receipt.MarshalCBOR(),
		Signature: h.StorageReceipt,
	}

	var check storage.MKVSReceipt
	return signed.Open(storage.MKVSReceiptSignatureContext, &check)
}

// VerifyStorageReceipt validates that the provided storage receipt
// matches the header.
func (h *Header) VerifyStorageReceipt(receipt *storage.MKVSReceiptBody) error {
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

// BatchSigMessage is batch attestation parameters.
//
// Keep the roothash RAK validation in sync with changes to this structure.
type BatchSigMessage struct {
	PreviousBlock Block     `codec:"previous_block"`
	IORoot        hash.Hash `codec:"io_root"`
	StateRoot     hash.Hash `codec:"state_root"`
}
