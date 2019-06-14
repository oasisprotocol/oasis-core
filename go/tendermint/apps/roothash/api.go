package roothash

import (
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the root hash application.
	TransactionTag byte = 0x02

	// AppName is the ABCI application name.
	AppName string = "999_roothash"
)

var (
	// TagUpdate is an ABCI transaction tag for marking transactions
	// which have been processed by roothash (value is TagUpdateValue).
	TagUpdate = []byte("roothash.update")
	// TagUpdateValue is the only allowed value for TagUpdate.
	TagUpdateValue = []byte("1")

	// TagMergeDiscrepancyDetected is an ABCI transaction tag for merge discrepancy
	// detected events (value is a CBOR serialized ValueMergeDiscrepancyDetected).
	TagMergeDiscrepancyDetected = []byte("roothash.merge-discrepancy")
	// TagComputeDiscrepancyDetected is an ABCI transaction tag for merge discrepancy
	// detected events (value is a CBOR serialized ValueComputeDiscrepancyDetected).
	TagComputeDiscrepancyDetected = []byte("roothash.compute-discrepancy")

	// TagFinalized is an ABCI transaction tag for finalized blocks
	// (value is a CBOR serialized ValueFinalized).
	TagFinalized = []byte("roothash.finalized")

	// QueryApp is a query for filtering transactions processed by
	// the root hash application.
	QueryApp = api.QueryForEvent([]byte(AppName), api.TagAppNameValue)

	// QueryUpdate is a query for filtering transactions where root hash
	// application state has been updated. This is required as state can
	//  change as part of foreign application transactions.
	QueryUpdate = api.QueryForEvent(TagUpdate, TagUpdateValue)
)

const (
	// QueryGetLatestBlock is a path for GetLatestBlock query.
	QueryGetLatestBlock = AppName + "/block"
)

// Tx is a transaction to be accepted by the roothash app.
type Tx struct {
	_struct struct{} `codec:",omitempty"` // nolint

	*TxComputeCommit `codec:"ComputeCommit"`
	*TxMergeCommit   `codec:"MergeCommit"`
}

// TxComputeCommit is a transaction for submitting compute commitments.
type TxComputeCommit struct {
	ID      signature.PublicKey            `codec:"id"`
	Commits []commitment.ComputeCommitment `codec:"commits"`
}

// TxMergeCommit is a transaction for submitting merge commitments.
type TxMergeCommit struct {
	ID      signature.PublicKey          `codec:"id"`
	Commits []commitment.MergeCommitment `codec:"commits"`
}

// ValueFinalized is the value component of a TagFinalized.
type ValueFinalized struct {
	ID    signature.PublicKey `codec:"id"`
	Round uint64              `codec:"round"`
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
	Event roothash.MergeDiscrepancyDetectedEvent `codec:"event"`
	ID    signature.PublicKey                    `codec:"id"`
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
	ID    signature.PublicKey                      `codec:"id"`
	Event roothash.ComputeDiscrepancyDetectedEvent `codec:"event"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueComputeDiscrepancyDetected) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueComputeDiscrepancyDetected) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}

// GenesisState is the roothash genesis state.
type GenesisState struct {
	// Blocks is the per-runtime map of genesis blocks.
	Blocks map[signature.MapKey]*block.Block `codec:"blocks,omit_empty"`
}
