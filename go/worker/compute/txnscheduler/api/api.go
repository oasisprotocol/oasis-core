package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/errors"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
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

	// ErrCheckTxFailed is the error returned when CheckTx fails.
	ErrCheckTxFailed = errors.New(ModuleName, 4, "txnscheduler: CheckTx failed")

	// ErrEpochNumberMismatch is the error returned when epoch of client and compute node mismatch.
	ErrEpochNumberMismatch = errors.New(ModuleName, 5, "txnscheduler: epoch number mismatch")
)

// TransactionScheduler is the transaction scheduler API interface.
type TransactionScheduler interface {
	// SubmitTx submits a new transaction to the transaction scheduler.
	SubmitTx(context.Context, *SubmitTxRequest) (*SubmitTxResponse, error)

	// IsTransactionQueued checks if the given transaction is present in the
	// transaction scheduler queue and is waiting to be dispatched to an
	// executor committee.
	IsTransactionQueued(context.Context, *IsTransactionQueuedRequest) (*IsTransactionQueuedResponse, error)
}

// SubmitTxRequest is a SubmitTx request.
type SubmitTxRequest struct {
	RuntimeID           common.Namespace    `json:"runtime_id"`
	ExpectedEpochNumber epochtime.EpochTime `json:"expected_epoch_number"`
	Data                []byte              `json:"data"`
}

// SubmitTxResponse is a SubmitTx response.
type SubmitTxResponse struct {
}

// IsTransactionQueuedRequest is an IsTransactionQueued request.
type IsTransactionQueuedRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	TxHash    hash.Hash        `json:"tx_hash"`
}

// IsTransactionQueuedResponse is an IsTransactionQueued response.
type IsTransactionQueuedResponse struct {
	IsQueued bool `json:"is_queued"`
}
