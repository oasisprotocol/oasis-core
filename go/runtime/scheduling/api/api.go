// Package api implements the transaction scheduler algorithm API.
package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// Scheduler defines an algorithm for scheduling incoming transactions.
type Scheduler interface {
	// Name is the scheduler algorithm name.
	Name() string

	// QueueTx queues a transaction for scheduling.
	QueueTx(tx []byte) error

	// AppendTxBatch appends a transaction batch for scheduling.
	//
	// Note: the AppendTxBatch is not required to be atomic. Semantics depend
	// on the specific scheduler implementation.
	AppendTxBatch(batch [][]byte) error

	// RemoveTxBatch removes a transaction batch.
	RemoveTxBatch(tx [][]byte) error

	// GetBatch returns a batch of scheduled transactions (if any is available).
	GetBatch(force bool) [][]byte

	// UnscheduledSize returns number of unscheduled items.
	UnscheduledSize() uint64

	// IsQueued returns if a transaction is queued.
	IsQueued(hash.Hash) bool

	// UpdateParameters updates the scheduling parameters.
	UpdateParameters(registry.TxnSchedulerParameters) error

	// Clear clears the transaction queue.
	Clear()
}
