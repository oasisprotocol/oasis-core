package merge

import (
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/computeenable"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

// New creates a new worker.
func New(commonWorker *workerCommon.Worker, registration *registration.Worker) (*Worker, error) {
	return newWorker(computeenable.Enabled(), commonWorker, registration)
}
