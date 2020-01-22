package merge

import (
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

// New creates a new worker.
func New(commonWorker *workerCommon.Worker, registration *registration.Worker) (*Worker, error) {
	return newWorker(compute.Enabled(), commonWorker, registration)
}
