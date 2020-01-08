package roothash

import (
	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x02

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
	// KeyExecutionDiscrepancyDetected is an ABCI event attribute key for
	// merge discrepancy detected events (value is a CBOR serialized
	// ValueExecutionDiscrepancyDetected).
	KeyExecutionDiscrepancyDetected = []byte("execution-discrepancy")
	// KeyFinalized is an ABCI event attribute key for finalized blocks
	// (value is a CBOR serialized ValueFinalized).
	KeyFinalized = []byte("finalized")
)

// ValueFinalized is the value component of a TagFinalized.
type ValueFinalized struct {
	ID    common.Namespace `json:"id"`
	Round uint64           `json:"round"`
}

// ValueMergeDiscrepancyDetected is the value component of a
// TagMergeDiscrepancyDetected.
type ValueMergeDiscrepancyDetected struct {
	Event roothash.MergeDiscrepancyDetectedEvent `json:"event"`
	ID    common.Namespace                       `json:"id"`
}

// ValueExecutionDiscrepancyDetected is the value component of a
// TagMergeDiscrepancyDetected.
type ValueExecutionDiscrepancyDetected struct {
	ID    common.Namespace                           `json:"id"`
	Event roothash.ExecutionDiscrepancyDetectedEvent `json:"event"`
}
