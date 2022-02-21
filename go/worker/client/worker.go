// Package client contains the runtime client worker.
package client

import (
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/worker/client/committee"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

// Worker is a runtime client worker handling many runtimes.
type Worker struct {
	enabled bool

	commonWorker *workerCommon.Worker

	runtimes map[common.Namespace]*committee.Node

	quitCh chan struct{}
	initCh chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "client worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Debug("not starting client worker as it is disabled")

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

	// Wait for all runtimes to be initialized.
	go func() {
		for _, rt := range w.runtimes {
			<-rt.Initialized()
		}

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

// Initialized returns a channel that will be closed when the client worker
// is initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

func (w *Worker) registerRuntime(commonNode *committeeCommon.Node) error {
	id := commonNode.Runtime.ID()

	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	// Create committee node for the given runtime.
	node, err := committee.NewNode(commonNode)
	if err != nil {
		return err
	}

	// If we are running in stateless client mode, register remote storage.
	if w.commonWorker.RuntimeRegistry.Mode() == runtimeRegistry.RuntimeModeClientStateless {
		commonNode.Runtime.RegisterStorage(NewStatelessStorage(commonNode.P2P, id))
	}

	commonNode.AddHooks(node)
	w.runtimes[id] = node

	w.logger.Info("new runtime registered",
		"runtime_id", id,
	)

	return nil
}

// New creates a new runtime client worker.
func New(grpcInternal *grpc.Server, commonWorker *workerCommon.Worker) (*Worker, error) {
	var enabled bool
	switch commonWorker.RuntimeRegistry.Mode() {
	case runtimeRegistry.RuntimeModeNone, runtimeRegistry.RuntimeModeKeymanager:
		enabled = false
	default:
		// When configured in one of the runtime modes, enable the client worker.
		enabled = true
	}

	w := &Worker{
		enabled:      enabled,
		commonWorker: commonWorker,
		runtimes:     make(map[common.Namespace]*committee.Node),
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		logger:       logging.GetLogger("worker/client"),
	}

	if !enabled {
		return w, nil
	}

	// Register all configured runtimes.
	for _, rt := range commonWorker.GetRuntimes() {
		if err := w.registerRuntime(rt); err != nil {
			return nil, err
		}
	}

	// Attach the runtime client worker's internal GRPC interface.
	api.RegisterService(grpcInternal.Server(), &service{w: w})

	return w, nil
}
