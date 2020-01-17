package executor

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	committeeCommon "github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/compute/executor/committee"
	"github.com/oasislabs/oasis-core/go/worker/compute/merge"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

// Worker is an executor worker handling many runtimes.
type Worker struct {
	*workerCommon.RuntimeHostWorker

	enabled bool

	commonWorker *workerCommon.Worker
	merge        *merge.Worker
	registration *registration.Worker

	runtimes map[common.Namespace]*committee.Node

	ctx       context.Context
	cancelCtx context.CancelFunc
	quitCh    chan struct{}
	initCh    chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "executor worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting executor worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for all runtimes and all proxies to terminate.
	go func() {
		defer close(w.quitCh)
		defer (w.cancelCtx)()

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

// Initialized returns a channel that will be closed when the executor worker
// is initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetRuntime returns a registered runtime.
//
// In case the runtime with the specified id was not registered it
// returns nil.
func (w *Worker) GetRuntime(id common.Namespace) *committee.Node {
	return w.runtimes[id]
}

func (w *Worker) registerRuntime(commonNode *committeeCommon.Node) error {
	id := commonNode.Runtime.ID()
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	// Get other nodes from this runtime.
	mergeNode := w.merge.GetRuntime(id)

	rp, err := w.registration.NewRuntimeRoleProvider(node.RoleComputeWorker, id)
	if err != nil {
		return fmt.Errorf("failed to create role provider: %w", err)
	}

	// Create worker host for the given runtime.
	workerHostFactory, err := w.NewRuntimeWorkerHostFactory(node.RoleComputeWorker, id)
	if err != nil {
		return fmt.Errorf("failed to create worker host: %w", err)
	}

	// Create committee node for the given runtime.
	node, err := committee.NewNode(commonNode, mergeNode, workerHostFactory, w.commonWorker.GetConfig(), rp)
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
	dataDir string,
	enabled bool,
	commonWorker *workerCommon.Worker,
	merge *merge.Worker,
	registration *registration.Worker,
) (*Worker, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())

	w := &Worker{
		enabled:      enabled,
		commonWorker: commonWorker,
		merge:        merge,
		registration: registration,
		runtimes:     make(map[common.Namespace]*committee.Node),
		ctx:          ctx,
		cancelCtx:    cancelCtx,
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		logger:       logging.GetLogger("worker/executor"),
	}

	if enabled {
		if !w.commonWorker.Enabled() {
			panic("common worker should have been enabled for executor worker")
		}

		// Create the runtime host worker.
		var err error
		w.RuntimeHostWorker, err = workerCommon.NewRuntimeHostWorker(commonWorker)
		if err != nil {
			return nil, err
		}

		// Register all configured runtimes.
		for _, rt := range commonWorker.GetRuntimes() {
			if err = w.registerRuntime(rt); err != nil {
				return nil, err
			}
		}
	}

	return w, nil
}
