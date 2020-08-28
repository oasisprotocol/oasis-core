package scheduling

import (
	"fmt"

	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple"
)

// New creates a new scheduler.
func New(maxQueueSize uint64, params registry.TxnSchedulerParameters) (api.Scheduler, error) {
	switch params.Algorithm {
	case simple.Name:
		return simple.New(maxQueueSize, params)
	default:
		return nil, fmt.Errorf("invalid transaction scheduler algorithm: %s", params.Algorithm)
	}
}
