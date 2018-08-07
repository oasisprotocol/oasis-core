package simulator

import (
	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

type TransactionSource interface {
	Get(seqno uint) (*alg.Transaction, error)
	Close() // Logging "source" needs to flush its buffers; and file readers should close.
}
