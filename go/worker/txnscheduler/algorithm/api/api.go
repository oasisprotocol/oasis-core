// Package api implements the transaction scheduler algorithm API.
package api

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/runtime"
)

// Algorithm defines an algorithm for scheduling incoming transaction.
type Algorithm interface {
	// Initialize initializes the internal transaction scheduler state.
	// Algorithm should use the provided transaction dispatcher to dispatch
	// scheduled transactions.
	Initialize(td TransactionDispatcher) error

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
	// XXX: when multiple committees per runtime are supported, add
	// committeeId here.
	Dispatch(batch runtime.Batch) error
}
