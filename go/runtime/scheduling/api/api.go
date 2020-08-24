// Package api implements the transaction scheduler algorithm API.
package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

// Scheduler defines an algorithm for scheduling incoming transactions.
type Scheduler interface {
	// Initialize initializes the internal scheduler state.
	// Scheduler should use the provided transaction dispatcher to dispatch
	// transactions.
	Initialize(td TransactionDispatcher) error

	// IsInitialized returns true, if the scheduler has been initialized.
	IsInitialized() bool

	// ScheduleTx attempts to schedule a transaction.
	//
	// The scheduling algorithm may peek into the transaction to extract
	// metadata needed for scheduling. In this case, the transaction bytes
	// must correspond to a transaction.TxnCall structure.
	ScheduleTx(tx []byte) error

	// AppendTxBatch appends a transaction batch for scheduling.
	//
	// Note: the AppendTxBatch is not required to be atomic. Semantics depend
	// on the specific scheduler implementation.
	AppendTxBatch(batch [][]byte) error

	// RemoveTxBatch removes a transaction batch.
	RemoveTxBatch(tx [][]byte) error

	// Flush flushes queued transactions.
	Flush(force bool) error

	// UnscheduledSize returns number of unscheduled items.
	UnscheduledSize() int

	// IsQueued returns if a transaction is queued.
	IsQueued(hash.Hash) bool

	// Clear clears the transaction queue.
	Clear()
}

// TransactionDispatcher dispatches transactions to a scheduled executor committee.
type TransactionDispatcher interface {
	// Dispatch attempts to dispatch a batch to a executor committee.
	Dispatch(batch transaction.RawBatch) error
}
