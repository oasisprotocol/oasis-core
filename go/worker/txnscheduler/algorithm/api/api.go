// Package api implements the transaction scheduler algorithm API.
package api

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	"github.com/oasislabs/ekiden/go/worker/common/committee"
)

// Algorithm defines an algorithm for scheduling incoming transaction.
type Algorithm interface {
	// Initialize initializes the internal transaction scheduler state.
	// Algorithm should use the provided transaction dispatcher to dispatch
	// scheduled transactions.
	Initialize(td TransactionDispatcher) error

	// EpochTransition notifies the transaction scheduler about a new
	// epoch transition, passing in an epoch snapshot.
	EpochTransition(epoch *committee.EpochSnapshot) error

	// ScheduleTx attempts to schedule a transaction.
	// XXX: When needed by more complex algorithms, extend the 'tx'
	// type to contain additional info.
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

// TransactionDispatcher dispatches transactions to a scheduled compute committee.
type TransactionDispatcher interface {
	// Dispatch attempts to dispatch a batch to a compute committee.
	Dispatch(committeeID hash.Hash, batch transaction.Batch) error
}
