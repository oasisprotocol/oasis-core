package common

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	keymanagerApi "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

// Worker is a garbage bag with lower level services and common runtime objects.
type Worker struct {
	enabled bool
	cfg     Config

	HostNode        control.NodeController
	DataDir         string
	ChainContext    string
	Identity        *identity.Identity
	Consensus       consensus.Service
	LightProvider   consensus.LightProvider
	P2P             p2p.Service
	KeyManager      keymanagerApi.Backend
	RuntimeRegistry runtimeRegistry.Registry
	Provisioner     host.Provisioner

	runtimes map[common.Namespace]*committee.Node

	quitCh chan struct{}
	initCh chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "common worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting common worker as it is disabled")

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

// Initialized returns a channel that will be closed when the transaction scheduler is
// initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetConfig returns the worker's configuration.
func (w *Worker) GetConfig() Config {
	return w.cfg
}

// GetRuntimes returns a map of configured runtimes.
func (w *Worker) GetRuntimes() map[common.Namespace]*committee.Node {
	return w.runtimes
}

// GetRuntime returns a common committee node for the given runtime (if available).
//
// In case the runtime with the specified id was not configured for this node it returns nil.
func (w *Worker) GetRuntime(id common.Namespace) *committee.Node {
	return w.runtimes[id]
}

func (w *Worker) registerRuntime(runtime runtimeRegistry.Runtime) error {
	id := runtime.ID()
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	node, err := committee.NewNode(
		w.ChainContext,
		w.HostNode,
		runtime,
		w.Provisioner,
		w.RuntimeRegistry,
		w.Identity,
		w.KeyManager,
		w.Consensus,
		w.LightProvider,
		w.P2P,
		w.cfg.TxPool,
		w.cfg.MetricsEnabled,
	)
	if err != nil {
		return err
	}
	w.runtimes[id] = node

	w.logger.Info("new runtime registered",
		"runtime_id", id,
	)

	return nil
}

// New creates a new worker.
func New(
	hostNode control.NodeController,
	dataDir string,
	chainContext string,
	identity *identity.Identity,
	consensus consensus.Service,
	lightProvider consensus.LightProvider,
	p2p p2p.Service,
	keyManager keymanagerApi.Backend,
	runtimeRegistry runtimeRegistry.Registry,
	provisioner host.Provisioner,
	metricsEnabled bool,
) (*Worker, error) {
	var enabled bool
	switch config.GlobalConfig.Mode {
	case config.ModeValidator, config.ModeSeed:
		enabled = false
	case config.ModeArchive:
		enabled = len(runtimeRegistry.Runtimes()) > 0
	default:
		// When configured in runtime mode, enable the common worker.
		enabled = true
	}

	cfg, err := NewConfig(metricsEnabled)
	if err != nil {
		return nil, fmt.Errorf("worker/common: failed to initialize config: %w", err)
	}

	w := &Worker{
		enabled:         enabled,
		cfg:             *cfg,
		HostNode:        hostNode,
		DataDir:         dataDir,
		ChainContext:    chainContext,
		Identity:        identity,
		Consensus:       consensus,
		LightProvider:   lightProvider,
		P2P:             p2p,
		KeyManager:      keyManager,
		RuntimeRegistry: runtimeRegistry,
		Provisioner:     provisioner,
		runtimes:        make(map[common.Namespace]*committee.Node),
		quitCh:          make(chan struct{}),
		initCh:          make(chan struct{}),
		logger:          logging.GetLogger("worker/common"),
	}

	if !enabled {
		return w, nil
	}

	// Register all configured managed runtimes.
	for _, rt := range runtimeRegistry.Runtimes() {
		if !rt.IsManaged() {
			continue
		}
		if err := w.registerRuntime(rt); err != nil {
			return nil, err
		}
	}

	return w, nil
}
