package scheduling

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple"
)

// New creates a new scheduler.
func New(name string, maxQueueSize, maxBatchSize, maxBatchSizeBytes uint64) (api.Scheduler, error) {
	switch name {
	case simple.Name:
		return simple.New(maxQueueSize, maxBatchSize, maxBatchSizeBytes)
	default:
		return nil, fmt.Errorf("invalid transaction scheduler algorithm: %s", name)
	}
}
