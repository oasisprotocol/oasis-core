package txnscheduler

import (
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	committeeCommon "github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	"github.com/oasislabs/oasis-core/go/worker/registration"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/api"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/committee"
)

// Worker is a transaction scheduler handling many runtimes.
type Worker struct {
	enabled bool

	commonWorker *workerCommon.Worker
	registration *registration.Worker
	compute      *compute.Worker

	runtimes map[signature.PublicKey]*committee.Node

	quitCh chan struct{}
	initCh chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "transaction scheduler"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting transaction scheduler as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for all runtimes to terminate.
	go func() {
		defer close(w.quitCh)

		for _, rt := range w.runtimes {
			<-rt.Quit()
		}
	}()

	// Wait for all runtimes to be initialized and for the node
	// to be registered for the current epoch.
	go func() {
		for _, rt := range w.runtimes {
			<-rt.Initialized()
		}

		<-w.registration.InitialRegistrationCh()

		close(w.initCh)
	}()

	// Start runtime services.
	for id, rt := range w.runtimes {
		w.logger.Info("starting services for runtime",
			"runtime_id", id,
		)

		if err := rt.Start(); err != nil {
			return err
		}
	}

	return nil
}

// Stop halts the service.
func (w *Worker) Stop() {
	if !w.enabled {
		close(w.quitCh)
		return
	}

	for id, rt := range w.runtimes {
		w.logger.Info("stopping services for runtime",
			"runtime_id", id,
		)

		rt.Stop()
	}
}

// Enabled returns if worker is enabled.
func (w *Worker) Enabled() bool {
	return w.enabled
}

// Quit returns a channel that will be closed when the service terminates.
func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (w *Worker) Cleanup() {
	if !w.enabled {
		return
	}

	for _, rt := range w.runtimes {
		rt.Cleanup()
	}
}

// Initialized returns a channel that will be closed when the transaction scheduler is
// initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetRuntime returns a registered runtime.
//
// In case the runtime with the specified id was not registered it
// returns nil.
func (w *Worker) GetRuntime(id signature.PublicKey) *committee.Node {
	return w.runtimes[id]
}

func (w *Worker) registerRuntime(commonNode *committeeCommon.Node) error {
	id := commonNode.Runtime.ID()
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	// Get other nodes from this runtime.
	computeNode := w.compute.GetRuntime(id)

	node, err := committee.NewNode(commonNode, computeNode)
	if err != nil {
		return err
	}

	commonNode.AddHooks(node)
	w.runtimes[id] = node

	w.logger.Info("new runtime registered",
		"runtime_id", id,
	)

	return nil
}

func newWorker(
	enabled bool,
	commonWorker *workerCommon.Worker,
	compute *compute.Worker,
	registration *registration.Worker,
) (*Worker, error) {
	w := &Worker{
		enabled:      enabled,
		commonWorker: commonWorker,
		registration: registration,
		compute:      compute,
		runtimes:     make(map[signature.PublicKey]*committee.Node),
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		logger:       logging.GetLogger("worker/txnscheduler"),
	}

	if enabled {
		if !w.commonWorker.Enabled() {
			panic("common worker should have been enabled for transaction scheduler")
		}

		// Use existing gRPC server passed from the node.
		api.RegisterService(commonWorker.Grpc.Server(), w)

		// Register all configured runtimes.
		for _, rt := range commonWorker.GetRuntimes() {
			if err := w.registerRuntime(rt); err != nil {
				return nil, err
			}
		}

		// Register transaction scheduler worker role.
		if err := w.registration.RegisterRole(node.RoleTransactionScheduler,
			func(n *node.Node) error { return nil }); err != nil {
			return nil, err
		}
	}

	return w, nil
}
