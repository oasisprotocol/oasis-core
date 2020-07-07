package roothash

import (
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
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

	// KeyRuntimeID is an ABCI event attribute key for specifying event
	// runtime.
	KeyRuntimeID = []byte("runtime-id")
	// KeyExecutorCommitted is an ABCI event attribute key for executor
	// commit events (value is CBOR-serialized ValueExecutorCommitted).
	KeyExecutorCommitted = []byte("executor-commit")
	// KeyMergeCommitted is an ABCI event attribute key for merge
	// commit events (value is CBOR-serialized ValueMergeCommitted).
	KeyMergeCommitted = []byte("merge-commit")
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

// ValueExecutorCommitted is the value component of a KeyExecutorCommitted.
type ValueExecutorCommitted struct {
	ID    common.Namespace                `json:"id"`
	Event roothash.ExecutorCommittedEvent `json:"event"`
}

// ValueMergeCommitted is the value component of a KeyMergeCommitted.
type ValueMergeCommitted struct {
	ID    common.Namespace             `json:"id"`
	Event roothash.MergeCommittedEvent `json:"event"`
}

// ValueFinalized is the value component of a TagFinalized.
type ValueFinalized struct {
	ID    common.Namespace `json:"id"`
	Round uint64           `json:"round"`
}

// ValueMergeDiscrepancyDetected is the value component of a KeyMergeDiscrepancyDetected.
type ValueMergeDiscrepancyDetected struct {
	Event roothash.MergeDiscrepancyDetectedEvent `json:"event"`
	ID    common.Namespace                       `json:"id"`
}

// ValueExecutionDiscrepancyDetected is the value component of a KeyMergeDiscrepancyDetected.
type ValueExecutionDiscrepancyDetected struct {
	ID    common.Namespace                           `json:"id"`
	Event roothash.ExecutionDiscrepancyDetectedEvent `json:"event"`
}
