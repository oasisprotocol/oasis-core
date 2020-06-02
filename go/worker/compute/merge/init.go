package merge

import (
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/compute"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

// New creates a new worker.
func New(commonWorker *workerCommon.Worker, registration *registration.Worker) (*Worker, error) {
	return newWorker(compute.Enabled(), commonWorker, registration)
}
