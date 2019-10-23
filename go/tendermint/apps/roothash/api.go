package roothash

import (
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the root hash application.
	TransactionTag byte = 0x02

	// AppName is the ABCI application name.
	AppName string = "999_roothash"
)

var (
	// EventType is the ABCI event type for roothash events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering transactions processed by the
	// roothash application.
	QueryApp = api.QueryForApp(AppName)

	// KeyMergeDiscrepancyDetected is an ABCI event attribute key for
	// merge discrepancy detected events (value is a CBOR serialized
	// ValueMergeDiscrepancyDetected).
	KeyMergeDiscrepancyDetected = []byte("merge-discrepancy")
	// KeyComputeDiscrepancyDetected is an ABCI event attribute key for
	// merge discrepancy detected events (value is a CBOR serialized
	// ValueComputeDiscrepancyDetected).
	KeyComputeDiscrepancyDetected = []byte("compute-discrepancy")
	// KeyFinalized is an ABCI event attribute key for finalized blocks
	// (value is a CBOR serialized ValueFinalized).
	KeyFinalized = []byte("finalized")
)

// Tx is a transaction to be accepted by the roothash app.
type Tx struct {
	*TxComputeCommit `json:"ComputeCommit,omitempty"`
	*TxMergeCommit   `json:"MergeCommit,omitempty"`
}

// TxComputeCommit is a transaction for submitting compute commitments.
type TxComputeCommit struct {
	ID      signature.PublicKey            `json:"id"`
	Commits []commitment.ComputeCommitment `json:"commits"`
}

// TxMergeCommit is a transaction for submitting merge commitments.
type TxMergeCommit struct {
	ID      signature.PublicKey          `json:"id"`
	Commits []commitment.MergeCommitment `json:"commits"`
}

// ValueFinalized is the value component of a TagFinalized.
type ValueFinalized struct {
	ID    signature.PublicKey `json:"id"`
	Round uint64              `json:"round"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueFinalized) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueFinalized) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}

// ValueMergeDiscrepancyDetected is the value component of a
// TagMergeDiscrepancyDetected.
type ValueMergeDiscrepancyDetected struct {
	Event roothash.MergeDiscrepancyDetectedEvent `json:"event"`
	ID    signature.PublicKey                    `json:"id"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueMergeDiscrepancyDetected) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueMergeDiscrepancyDetected) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}

// ValueComputeDiscrepancyDetected is the value component of a
// TagMergeDiscrepancyDetected.
type ValueComputeDiscrepancyDetected struct {
	ID    signature.PublicKey                      `json:"id"`
	Event roothash.ComputeDiscrepancyDetectedEvent `json:"event"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueComputeDiscrepancyDetected) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueComputeDiscrepancyDetected) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}
