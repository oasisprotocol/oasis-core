// Package api implements the transaction scheduler algorithm API.
package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

// Algorithm defines an algorithm for scheduling incoming transaction.
type Algorithm interface {
	// Initialize initializes the internal transaction scheduler state.
	// Algorithm should use the provided transaction dispatcher to dispatch
	// scheduled transactions.
	Initialize(td TransactionDispatcher) error

	// IsInitialized returns true, if an algorithm has been initialized.
	IsInitialized() bool

	// ScheduleTx attempts to schedule a transaction.
	//
	// The scheduling algorithm may peek into the transaction to extract
	// metadata needed for scheduling. In this case, the transaction bytes
	// must correspond to a transaction.TxnCall structure.
	ScheduleTx(tx []byte) error

	// Flush flushes queued transactions.
	Flush() error

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
