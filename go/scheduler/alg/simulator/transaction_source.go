package simulator

import (
	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

// TransactionSource is a simple interface for a source of transactions to be used in the simulator.
type TransactionSource interface {
	// Get a new Transaction. The error return value is non-nil if there is an error or if
	// the source is exhausted (end-of-file, total number desired already generated, etc).
	Get(tid int) (*alg.Transaction, error)

	// Close is used to do whatever wrap up is needed, e.g., flushing output buffers (for
	// logging transactions), closing I/O descriptors (for logging or replaying-from-file
	// as a source).
	Close() error // Logging "source" needs to flush its buffers; and file readers should close.
}
