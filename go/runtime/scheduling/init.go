package scheduling

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/priorityqueue"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

// New creates a new scheduler.
func New(maxTxPoolSize uint64, algo string, weightLimits map[transaction.Weight]uint64) (api.Scheduler, error) {
	switch algo {
	case simple.Name:
		return simple.New(priorityqueue.Name, maxTxPoolSize, algo, weightLimits)
	default:
		return nil, fmt.Errorf("invalid transaction scheduler algorithm: %s", algo)
	}
}
