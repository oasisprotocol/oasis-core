package txnscheduler

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	computeCommittee "github.com/oasislabs/oasis-core/go/worker/compute/committee"
	"github.com/oasislabs/oasis-core/go/worker/registration"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/api"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/committee"
)

// RuntimeConfig is a single runtime's configuration.
type RuntimeConfig struct {
	ID signature.PublicKey
}

// Config is the transaction scheduler configuration.
type Config struct {
	Backend  string
	Runtimes []RuntimeConfig
}

// Runtime is a single runtime.
type Runtime struct {
	cfg *RuntimeConfig

	node *committee.Node
}

// GetNode returns the committee node for this runtime.
func (r *Runtime) GetNode() *committee.Node {
	if r == nil {
		return nil
	}
	return r.node
}

// Worker is a transaction scheduler handling many runtimes.
type Worker struct {
	enabled bool
	cfg     Config

	commonWorker *workerCommon.Worker
	registration *registration.Worker
	compute      *compute.Worker

	runtimes map[signature.PublicKey]*Runtime

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
			"runtime_id", rt.cfg.ID,
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
			"runtime_id", rt.cfg.ID,
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

// Initialized returns a channel that will be closed when the transaction scheduler is
// initialized and ready to service requests.
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
	rt, ok := w.runtimes[id]
	if !ok {
		return nil
	}

	return rt
}

func (w *Worker) registerRuntime(cfg *Config, rtCfg *RuntimeConfig) error {
	w.logger.Info("registering new runtime",
		"runtime_id", rtCfg.ID,
	)

	// Get other nodes from this runtime.
	commonNode := w.commonWorker.GetRuntime(rtCfg.ID).GetNode()
	var computeNode *computeCommittee.Node
	if w.compute.Enabled() {
		computeNode = w.compute.GetRuntime(rtCfg.ID).GetNode()
	}

	node, err := committee.NewNode(
		commonNode,
		computeNode,
	)
	if err != nil {
		return err
	}

	commonNode.AddHooks(node)

	rt := &Runtime{
		cfg:  rtCfg,
		node: node,
	}
	w.runtimes[rt.cfg.ID] = rt

	w.logger.Info("new runtime registered",
		"runtime_id", rt.cfg.ID,
	)

	return nil
}

func newWorker(
	enabled bool,
	commonWorker *workerCommon.Worker,
	compute *compute.Worker,
	registration *registration.Worker,
	cfg Config,
) (*Worker, error) {
	w := &Worker{
		enabled:      enabled,
		cfg:          cfg,
		commonWorker: commonWorker,
		registration: registration,
		compute:      compute,
		runtimes:     make(map[signature.PublicKey]*Runtime),
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		logger:       logging.GetLogger("worker/txnscheduler"),
	}

	if enabled {
		if !w.commonWorker.Enabled() {
			panic("common worker should have been enabled for transaction scheduler")
		}

		if len(cfg.Runtimes) == 0 {
			return nil, fmt.Errorf("txnscheduler/worker: no runtimes configured")
		}

		// Use existing gRPC server passed from the node.
		api.RegisterService(commonWorker.Grpc.Server(), w)

		// Register all configured runtimes.
		for _, rtCfg := range cfg.Runtimes {
			if err := w.registerRuntime(&cfg, &rtCfg); err != nil {
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
