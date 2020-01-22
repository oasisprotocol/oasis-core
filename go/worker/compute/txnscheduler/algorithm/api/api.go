// Package api implements the transaction scheduler algorithm API.
package api

import (
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
)

// Algorithm defines an algorithm for scheduling incoming transaction.
type Algorithm interface {
	// Initialize initializes the internal transaction scheduler state.
	// Algorithm should use the provided transaction dispatcher to dispatch
	// scheduled transactions.
	Initialize(td TransactionDispatcher) error

	// IsInitialized returns true, if an algorithm has been initialized.
	IsInitialized() bool

	// EpochTransition notifies the transaction scheduler about a new
	// epoch transition, passing in an epoch snapshot.
	EpochTransition(epoch *committee.EpochSnapshot) error

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
	Dispatch(committeeID hash.Hash, batch transaction.RawBatch) error
}
