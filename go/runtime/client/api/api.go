package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

const (
	// ModuleName is the runtime client module name.
	ModuleName = "runtime/client"

	// RoundLatest is a special round number always referring to the latest round.
	RoundLatest = roothash.RoundLatest
)

var (
	// ErrNotFound is an error returned when the item is not found.
	ErrNotFound = errors.New(ModuleName, 1, "client: not found")
	// ErrInternal is an error returned when an unspecified internal error occurs.
	ErrInternal = errors.New(ModuleName, 2, "client: internal error")
	// ErrTransactionExpired is an error returned when transaction expired.
	ErrTransactionExpired = errors.New(ModuleName, 3, "client: transaction expired")
	// ErrNotSynced is an error returned if transaction is submitted before node has finished
	// initial syncing.
	ErrNotSynced = errors.New(ModuleName, 4, "client: not finished initial sync")
	// ErrCheckTxFailed is an error returned if the local transaction check fails.
	ErrCheckTxFailed = errors.New(ModuleName, 5, "client: transaction check failed")
	// ErrNoHostedRuntime is returned when the hosted runtime is not available locally.
	ErrNoHostedRuntime = errors.New(ModuleName, 6, "client: no hosted runtime is available")
)

// RuntimeClient is the runtime client interface.
type RuntimeClient interface {
	// SubmitTx submits a transaction to the runtime transaction scheduler and waits
	// for transaction execution results.
	SubmitTx(ctx context.Context, request *SubmitTxRequest) ([]byte, error)

	// SubmitTxMeta submits a transaction to the runtime transaction scheduler and waits for
	// transaction execution results.
	//
	// Response includes transaction metadata - e.g. round at which the transaction was included
	// in a block.
	SubmitTxMeta(ctx context.Context, request *SubmitTxRequest) (*SubmitTxMetaResponse, error)

	// SubmitTxNoWait submits a transaction to the runtime transaction scheduler but does
	// not wait for transaction execution.
	SubmitTxNoWait(ctx context.Context, request *SubmitTxRequest) error

	// CheckTx asks the local runtime to check the specified transaction.
	CheckTx(ctx context.Context, request *CheckTxRequest) error

	// GetGenesisBlock returns the genesis block.
	GetGenesisBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error)

	// GetBlock fetches the given runtime block.
	GetBlock(ctx context.Context, request *GetBlockRequest) (*block.Block, error)

	// GetLastRetainedBlock returns the last retained block.
	GetLastRetainedBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error)

	// GetTransactions fetches all runtime transactions in a given block.
	GetTransactions(ctx context.Context, request *GetTransactionsRequest) ([][]byte, error)

	// GetTransactionsWithResults fetches all runtime transactions in a given block together with
	// its results (outputs and emitted events).
	GetTransactionsWithResults(ctx context.Context, request *GetTransactionsRequest) ([]*TransactionWithResults, error)

	// GetEvents returns all events emitted in a given block.
	GetEvents(ctx context.Context, request *GetEventsRequest) ([]*Event, error)

	// Query makes a runtime-specific query.
	Query(ctx context.Context, request *QueryRequest) (*QueryResponse, error)

	// WatchBlocks subscribes to blocks for a specific runtimes.
	WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error)
}

// SubmitTxResult is the raw result of submitting a transaction for processing.
type SubmitTxResult struct {
	Error  error
	Result *SubmitTxMetaResponse
}

// SubmitTxRequest is a SubmitTx request.
type SubmitTxRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Data      []byte           `json:"data"`
}

// SubmitTxMetaResponse is the SubmitTxMeta response.
type SubmitTxMetaResponse struct {
	// Output is the transaction output.
	Output []byte `json:"data,omitempty"`
	// Round is the roothash round in which the transaction was executed.
	Round uint64 `json:"round,omitempty"`
	// BatchOrder is the order of the transaction in the execution batch.
	BatchOrder uint32 `json:"batch_order,omitempty"`

	// CheckTxError is the CheckTx error in case transaction failed the transaction check.
	CheckTxError *protocol.Error `json:"check_tx_error,omitempty"`
}

// CheckTxRequest is a CheckTx request.
type CheckTxRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Data      []byte           `json:"data"`
}

// GetBlockRequest is a GetBlock request.
type GetBlockRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
}

// GetTransactionsRequest is a GetTransactions request.
type GetTransactionsRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
}

// TransactionWithResults is a transaction with its raw result and emitted events.
type TransactionWithResults struct {
	Tx     []byte        `json:"tx"`
	Result []byte        `json:"result"`
	Events []*PlainEvent `json:"events,omitempty"`
}

// GetEventsRequest is a GetEvents request.
type GetEventsRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
}

// Event is an event emitted by a runtime in the form of a runtime transaction tag.
//
// Key and value semantics are runtime-dependent.
type Event struct {
	Key    []byte    `json:"key"`
	Value  []byte    `json:"value"`
	TxHash hash.Hash `json:"tx_hash"`
}

// PlainEvent is an event emitted by a runtime in the form of a runtime transaction tag. It
// does not include the transaction hash.
//
// Key and value semantics are runtime-dependent.
type PlainEvent struct {
	Key   []byte `json:"key"`
	Value []byte `json:"value"`
}

// QueryRequest is a Query request.
type QueryRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
	Method    string           `json:"method"`
	Args      []byte           `json:"args"`
}

// QueryResponse is a response to the runtime query.
type QueryResponse struct {
	Data []byte `json:"data"`
}
