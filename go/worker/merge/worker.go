package merge

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/merge/committee"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

// Runtime is a single runtime.
type Runtime struct {
	id   signature.PublicKey
	node *committee.Node
}

// GetNode returns the committee node for this runtime.
func (r *Runtime) GetNode() *committee.Node {
	if r == nil {
		return nil
	}
	return r.node
}

// Config is the merge worker configuration.
type Config struct {
	Committee committee.Config
}

// Worker is a merge worker.
type Worker struct {
	enabled bool
	cfg     Config

	commonWorker       *workerCommon.Worker
	registrationWorker *registration.Worker

	runtimes map[signature.PublicKey]*Runtime

	ctx       context.Context
	cancelCtx context.CancelFunc
	quitCh    chan struct{}
	initCh    chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "merge worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting merge worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for all runtimes to terminate.
	go func() {
		defer close(w.quitCh)

		for _, rt := range w.runtimes {
			<-rt.node.Quit()
		}
	}()

	// Wait for all runtimes to be initialized and for the node
	// to be registered for the current epoch.
	go func() {
		for _, rt := range w.runtimes {
			<-rt.node.Initialized()
		}

		<-w.registrationWorker.InitialRegistrationCh()

		close(w.initCh)
	}()

	// Start runtime services.
	for _, rt := range w.runtimes {
		w.logger.Info("starting services for runtime",
			"runtime_id", rt.id,
		)

		if err := rt.node.Start(); err != nil {
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

	for _, rt := range w.runtimes {
		w.logger.Info("stopping services for runtime",
			"runtime_id", rt.id,
		)

		rt.node.Stop()
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
		rt.node.Cleanup()
	}
}

// Initialized returns a channel that will be closed when the merge worker
// is initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetRuntime returns a registered runtime.
//
// In case the runtime with the specified id was not registered it
// returns nil.
func (w *Worker) GetRuntime(id signature.PublicKey) *Runtime {
	rt, ok := w.runtimes[id]
	if !ok {
		return nil
	}

	return rt
}

func (w *Worker) registerRuntime(id signature.PublicKey) error {
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	// Get other nodes from this runtime.
	commonNode := w.commonWorker.GetRuntime(id).GetNode()

	node, err := committee.NewNode(
		commonNode,
		w.cfg.Committee,
	)
	if err != nil {
		return err
	}

	commonNode.AddHooks(node)

	rt := &Runtime{
		id:   id,
		node: node,
	}
	w.runtimes[id] = rt

	w.logger.Info("new runtime registered",
		"runtime_id", id,
	)

	return nil
}

func newWorker(
	enabled bool,
	commonWorker *workerCommon.Worker,
	registrationWorker *registration.Worker,
	cfg Config,
) (*Worker, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())

	w := &Worker{
		enabled:            enabled,
		cfg:                cfg,
		commonWorker:       commonWorker,
		registrationWorker: registrationWorker,
		runtimes:           make(map[signature.PublicKey]*Runtime),
		ctx:                ctx,
		cancelCtx:          cancelCtx,
		quitCh:             make(chan struct{}),
		initCh:             make(chan struct{}),
		logger:             logging.GetLogger("worker/merge"),
	}

	if enabled {
		if !w.commonWorker.Enabled() {
			panic("common worker should have been enabled for merge worker")
		}

		// Register all configured runtimes.
		for _, runtimeID := range commonWorker.GetConfig().Runtimes {
			if err := w.registerRuntime(runtimeID); err != nil {
				return nil, err
			}
		}

		// Register merge worker role.
		if err := w.registrationWorker.RegisterRole(node.RoleMergeWorker,
			func(n *node.Node) error { return nil }); err != nil {
			return nil, err
		}
	}

	return w, nil
}
