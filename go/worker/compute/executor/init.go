package executor

import (
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/compute"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/merge"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

// New creates a new executor worker.
func New(
	dataDir string,
	commonWorker *workerCommon.Worker,
	mergeWorker *merge.Worker,
	registration *registration.Worker,
) (*Worker, error) {
	return newWorker(dataDir, compute.Enabled(), commonWorker, mergeWorker, registration)
}
