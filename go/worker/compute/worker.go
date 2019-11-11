package compute

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/compute/committee"
	"github.com/oasislabs/oasis-core/go/worker/merge"
	mergeCommittee "github.com/oasislabs/oasis-core/go/worker/merge/committee"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

// Config is the compute worker configuration.
type Config struct {
	// Committee is the compute committee configuration.
	Committee committee.Config
}

// Runtime is a single runtime.
type Runtime struct {
	id signature.PublicKey

	node *committee.Node
}

// GetNode returns the committee node for this runtime.
func (r *Runtime) GetNode() *committee.Node {
	if r == nil {
		return nil
	}
	return r.node
}

// Worker is a compute worker handling many runtimes.
type Worker struct {
	*workerCommon.RuntimeHostWorker

	enabled bool
	cfg     Config

	commonWorker *workerCommon.Worker
	merge        *merge.Worker
	registration *registration.Worker

	runtimes map[signature.MapKey]*Runtime

	ctx       context.Context
	cancelCtx context.CancelFunc
	quitCh    chan struct{}
	initCh    chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "compute worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting compute worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for all runtimes and all proxies to terminate.
	go func() {
		defer close(w.quitCh)
		defer (w.cancelCtx)()

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

		<-w.registration.InitialRegistrationCh()

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

// Initialized returns a channel that will be closed when the compute worker
// is initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetConfig returns the worker's configuration.
func (w *Worker) GetConfig() Config {
	return w.cfg
}

// GetRuntime returns a registered runtime.
//
// In case the runtime with the specified id was not registered it
// returns nil.
func (w *Worker) GetRuntime(id signature.PublicKey) *Runtime {
	rt, ok := w.runtimes[id.ToMapKey()]
	if !ok {
		return nil
	}

	return rt
}

func (w *Worker) registerRuntime(cfg *Config, rt *workerCommon.Runtime) error {
	w.logger.Info("registering new runtime",
		"runtime_id", rt.GetID(),
	)

	// Get other nodes from this runtime.
	commonNode := rt.GetNode()
	var mergeNode *mergeCommittee.Node
	if w.merge.Enabled() {
		mergeNode = w.merge.GetRuntime(rt.GetID()).GetNode()
	}

	// Create worker host for the given runtime.
	workerHostFactory, err := w.NewRuntimeWorkerHostFactory(node.RoleComputeWorker, rt.GetID())
	if err != nil {
		return err
	}

	// Create committee node for the given runtime.
	node, err := committee.NewNode(
		commonNode,
		mergeNode,
		workerHostFactory,
		cfg.Committee,
	)
	if err != nil {
		return err
	}

	commonNode.AddHooks(node)

	crt := &Runtime{
		id:   rt.GetID(),
		node: node,
	}
	w.runtimes[crt.id.ToMapKey()] = crt

	w.logger.Info("new runtime registered",
		"runtime_id", rt.GetID(),
	)

	return nil
}

func newWorker(
	dataDir string,
	enabled bool,
	commonWorker *workerCommon.Worker,
	merge *merge.Worker,
	registration *registration.Worker,
	cfg Config,
) (*Worker, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())

	w := &Worker{
		enabled:      enabled,
		cfg:          cfg,
		commonWorker: commonWorker,
		merge:        merge,
		registration: registration,
		runtimes:     make(map[signature.MapKey]*Runtime),
		ctx:          ctx,
		cancelCtx:    cancelCtx,
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		logger:       logging.GetLogger("worker/compute"),
	}

	if enabled {
		if !w.commonWorker.Enabled() {
			panic("common worker should have been enabled for compute worker")
		}

		// Create the runtime host worker.
		var err error
		w.RuntimeHostWorker, err = workerCommon.NewRuntimeHostWorker(commonWorker)
		if err != nil {
			return nil, err
		}

		// Register all configured runtimes.
		for _, rt := range commonWorker.GetRuntimes() {
			if err := w.registerRuntime(&cfg, rt); err != nil {
				return nil, err
			}
		}

		// Register compute worker role.
		w.registration.RegisterRole(func(n *node.Node) error {
			n.AddRoles(node.RoleComputeWorker)

			// Wait until all the runtimes are initialized.
			for _, rt := range w.runtimes {
				select {
				case <-rt.node.Initialized():
				case <-w.ctx.Done():
					return w.ctx.Err()
				}
			}

			for _, rt := range n.Runtimes {
				var err error

				workerRT := w.runtimes[rt.ID.ToMapKey()]
				if workerRT == nil {
					continue
				}

				workerHost := workerRT.GetNode().GetWorkerHost()
				if workerHost == nil {
					w.logger.Debug("runtime has shut down",
						"runtime", rt.ID,
					)
					continue
				}
				if rt.Capabilities.TEE, err = workerHost.WaitForCapabilityTEE(w.ctx); err != nil {
					w.logger.Error("failed to obtain CapabilityTEE",
						"err", err,
						"runtime", rt.ID,
					)
					continue
				}

				runtimeVersion, err := workerHost.WaitForRuntimeVersion(w.ctx)
				if err == nil && runtimeVersion != nil {
					rt.Version = *runtimeVersion
				} else {
					w.logger.Error("failed to obtain RuntimeVersion",
						"err", err,
						"runtime", rt.ID,
						"runtime_version", runtimeVersion,
					)
					continue
				}
			}

			return nil
		})
	}

	return w, nil
}
