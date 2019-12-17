package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
)

// ModuleName is the transaction scheduler module name.
const ModuleName = "worker/txnscheduler"

var (
	// ErrUnknownRuntime is the error returned when the passed runtime identifier
	// does not belong to a known runtime.
	ErrUnknownRuntime = errors.New(ModuleName, 1, "txnscheduler: unknown runtime")

	// ErrNotLeader is the error returned when the transaction scheduler does not
	// currently consider itself a leader.
	ErrNotLeader = errors.New(ModuleName, 2, "txnscheduler: not leader")

	// ErrNotReady is the error returned when the transaction scheduler is not
	// yet ready to process transactions.
	ErrNotReady = errors.New(ModuleName, 3, "txnscheduler: not ready")
)

// TransactionScheduler is the transaction scheduler API interface.
type TransactionScheduler interface {
	// SubmitTx submits a new transaction to the transaction scheduler.
	SubmitTx(context.Context, *SubmitTxRequest) (*SubmitTxResponse, error)

	// IsTransactionQueued checks if the given transaction is present in the
	// transaction scheduler queue and is waiting to be dispatched to a
	// compute committee.
	IsTransactionQueued(context.Context, *IsTransactionQueuedRequest) (*IsTransactionQueuedResponse, error)
}

// SubmitTxRequest is a SubmitTx request.
type SubmitTxRequest struct {
	RuntimeID signature.PublicKey `json:"runtime_id"`
	Data      []byte              `json:"data"`
}

// SubmitTxResponse is a SubmitTx response.
type SubmitTxResponse struct {
}

// IsTransactionQueuedRequest is an IsTransactionQueued request.
type IsTransactionQueuedRequest struct {
	RuntimeID signature.PublicKey `json:"runtime_id"`
	TxHash    hash.Hash           `json:"tx_hash"`
}

// IsTransactionQueuedResponse is an IsTransactionQueued response.
type IsTransactionQueuedResponse struct {
	IsQueued bool `json:"is_queued"`
}
