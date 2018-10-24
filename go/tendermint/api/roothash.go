package api

import (
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
)

const (
	// RootHashTransactionTag is a unique byte used to identify
	// transactions for the root hash application.
	RootHashTransactionTag byte = 0x02

	// RootHashAppName is the ABCI application name.
	RootHashAppName string = "roothash"
)

var (
	// TagRootHashUpdate is an ABCI transaction tag for marking transactions
	// which have been processed by roothash (value is TagRootHashUpdateValue).
	TagRootHashUpdate = []byte("roothash.update")
	// TagRootHashUpdateValue is the only allowed value for TagRootHashUpdate.
	TagRootHashUpdateValue = []byte("1")

	// TagRootHashDiscrepancyDetected is an ABCI transaction tag for
	// discrepancy detected events (value is a CBOR serialized
	// ValueRootHashDiscrepancyDetected).
	TagRootHashDiscrepancyDetected = []byte("roothash.discrepancy")

	// TagRootHashFinalized is an ABCI transaction tag for finalized
	// blocks (value is a CBOR serialized ValueRootHashFinalized).
	TagRootHashFinalized = []byte("roothash.finalized")
)

const (
	// QueryRootHashGetLatestBlock is a path for GetLatestBlock query.
	QueryRootHashGetLatestBlock = "roothash/block"
)

var (
	// QueryRootHashApp is a query for filtering transactions processed by
	// the root hash application.
	QueryRootHashApp = QueryForEvent(TagApplication, []byte(RootHashAppName))

	// QueryRootHashUpdate is a query for filtering transactions where root
	// hash application state has been updated. This is required as state
	// can change as part of foreign application transactions.
	QueryRootHashUpdate = QueryForEvent(TagRootHashUpdate, TagRootHashUpdateValue)
)

// TxRootHash is a transaction to be accepted by the roothash app.
type TxRootHash struct {
	_struct struct{} `codec:",omitempty"` // nolint

	*TxCommit `codec:"Commit"`
}

// TxCommit is a transaction for submitting a roothash commitment.
type TxCommit struct {
	ID         signature.PublicKey
	Commitment roothash.Commitment
}

// QueryGetLatestBlock is a request for fetching the latest block.
type QueryGetLatestBlock struct {
	ID signature.PublicKey
}

// ValueRootHashFinalized is the value component of a TagRootHashFinalized.
type ValueRootHashFinalized struct {
	ID    signature.PublicKey `codec:"id"`
	Round uint64              `codec:"round"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueRootHashFinalized) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueRootHashFinalized) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}

// ValueRootHashDiscrepancyDetected is the value component of a
// TagRootHashDiscrepancyDetected.
type ValueRootHashDiscrepancyDetected struct {
	ID    signature.PublicKey               `codec:"id"`
	Event roothash.DiscrepancyDetectedEvent `codec:"event"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueRootHashDiscrepancyDetected) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueRootHashDiscrepancyDetected) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}
