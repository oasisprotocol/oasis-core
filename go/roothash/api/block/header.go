package block

import (
	"errors"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

// ErrInvalidVersion is the error returned when a version is invalid.
var ErrInvalidVersion = errors.New("roothash: invalid version")

// HeaderType is the type of header.
type HeaderType uint8

// Timestamp is a custom time stamp type that encodes like time.Time when
// marshaling to text.
type Timestamp uint64

// MarshalText encodes a Timestamp to text by converting it from Unix time to
// local time.
func (ts Timestamp) MarshalText() ([]byte, error) {
	t := time.Unix(int64(ts), 0)
	return t.MarshalText()
}

// UnmarshalText decodes a text slice into a Timestamp.
func (ts *Timestamp) UnmarshalText(data []byte) error {
	var t time.Time
	err := t.UnmarshalText(data)
	if err != nil {
		return err
	}
	*ts = Timestamp(t.Unix())
	return nil
}

const (
	// Invalid is an invalid header type and should never be stored.
	Invalid HeaderType = 0

	// Normal is a normal header.
	Normal HeaderType = 1

	// RoundFailed is a header resulting from a failed round. Such a
	// header contains no transactions but advances the round as normal
	// to prevent replays of old commitments.
	RoundFailed HeaderType = 2

	// EpochTransition is a header resulting from an epoch transition.
	//
	// Such a header contains no transactions but advances the round as
	// normal.
	// TODO: Consider renaming this to CommitteeTransition.
	EpochTransition HeaderType = 3

	// Suspended is a header resulting from the runtime being suspended.
	//
	// Such a header contains no transactions but advances the round as
	// normal.
	Suspended HeaderType = 4
)

// Header is a block header.
//
// Keep this in sync with /runtime/src/common/roothash.rs.
type Header struct { // nolint: maligned
	// Version is the protocol version number.
	Version uint16 `json:"version"`

	// Namespace is the header's chain namespace.
	Namespace common.Namespace `json:"namespace"`

	// Round is the block round.
	Round uint64 `json:"round"`

	// Timestamp is the block timestamp (POSIX time).
	Timestamp Timestamp `json:"timestamp"`

	// HeaderType is the header type.
	HeaderType HeaderType `json:"header_type"`

	// PreviousHash is the previous block hash.
	PreviousHash hash.Hash `json:"previous_hash"`

	// IORoot is the I/O merkle root.
	IORoot hash.Hash `json:"io_root"`

	// StateRoot is the state merkle root.
	StateRoot hash.Hash `json:"state_root"`

	// MessagesHash is the hash of emitted runtime messages.
	MessagesHash hash.Hash `json:"messages_hash"`

	// InMessagesHash is the hash of processed incoming messages.
	InMessagesHash hash.Hash `json:"in_msgs_hash"`
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
	aHash, bHash := h.EncodedHash(), cmp.EncodedHash()
	return aHash.Equal(&bHash)
}

// EncodedHash returns the encoded cryptographic hash of the header.
func (h *Header) EncodedHash() hash.Hash {
	return hash.NewFrom(h)
}

// StorageRoots returns the storage roots contained in this header.
func (h *Header) StorageRoots() []storage.Root {
	return []storage.Root{
		{
			Namespace: h.Namespace,
			Version:   h.Round,
			Type:      storage.RootTypeIO,
			Hash:      h.IORoot,
		},
		{
			Namespace: h.Namespace,
			Version:   h.Round,
			Type:      storage.RootTypeState,
			Hash:      h.StateRoot,
		},
	}
}
