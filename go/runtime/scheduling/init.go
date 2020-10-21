package scheduling

import (
	"fmt"

	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/orderedmap"
)

// New creates a new scheduler.
func New(maxTxPoolSize uint64, params registry.TxnSchedulerParameters) (api.Scheduler, error) {
	switch params.Algorithm {
	case simple.Name:
		return simple.New(orderedmap.Name, maxTxPoolSize, params)
	default:
		return nil, fmt.Errorf("invalid transaction scheduler algorithm: %s", params.Algorithm)
	}
}
