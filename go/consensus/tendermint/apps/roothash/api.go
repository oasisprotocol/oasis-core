package roothash

import (
	"fmt"

	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"

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
	// runtime (value is Base64-encoded runtime ID).
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
	// KeyMessage is an ABCI event attribute key for message result events
	// (value is a CBOR serialized ValueMessage).
	KeyMessage = []byte("message")
)

// QueryForRuntime returns a query for filtering transactions processed by the roothash application
// limited to a specific runtime.
func QueryForRuntime(runtimeID common.Namespace) tmpubsub.Query {
	return tmquery.MustParse(fmt.Sprintf("%s AND %s.%s='%s'", QueryApp, EventType, KeyRuntimeID, ValueRuntimeID(runtimeID)))
}

// ValueRuntimeID returns the value that should be stored under KeyRuntimeID.
func ValueRuntimeID(runtimeID common.Namespace) []byte {
	// This needs to be a text field as Tendermint does not support non-text queries.
	tagRuntimeID, _ := runtimeID.MarshalText()
	return tagRuntimeID
}

// ValueExecutorCommitted is the value component of a KeyExecutorCommitted.
type ValueExecutorCommitted struct {
	ID    common.Namespace                `json:"id"`
	Event roothash.ExecutorCommittedEvent `json:"event"`
}

// ValueFinalized is the value component of a TagFinalized.
type ValueFinalized struct {
	ID    common.Namespace `json:"id"`
	Round uint64           `json:"round"`
}

// ValueExecutionDiscrepancyDetected is the value component of a KeyMergeDiscrepancyDetected.
type ValueExecutionDiscrepancyDetected struct {
	ID    common.Namespace                           `json:"id"`
	Event roothash.ExecutionDiscrepancyDetectedEvent `json:"event"`
}

// ValueMessage is the value component of a KeyMessage.
type ValueMessage struct {
	ID    common.Namespace      `json:"id"`
	Event roothash.MessageEvent `json:"event"`
}
