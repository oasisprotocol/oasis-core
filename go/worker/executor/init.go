package executor

import (
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	"github.com/oasislabs/oasis-core/go/worker/merge"
	"github.com/oasislabs/oasis-core/go/worker/registration"
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
