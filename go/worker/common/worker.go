package common

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	policyAPI "github.com/oasisprotocol/oasis-core/go/common/grpc/policy/api"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	keymanagerApi "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/sentry/policywatcher"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
)

// Worker is a garbage bag with lower level services and common runtime objects.
type Worker struct {
	enabled bool
	cfg     Config

	DataDir           string
	Identity          *identity.Identity
	Consensus         consensus.Backend
	Grpc              *grpc.Server
	GrpcPolicyWatcher policyAPI.PolicyWatcher
	P2P               *p2p.P2P
	IAS               ias.Endpoint
	KeyManager        keymanagerApi.Backend
	RuntimeRegistry   runtimeRegistry.Registry
	GenesisDoc        *genesis.Document

	runtimes map[common.Namespace]*committee.Node

	ctx       context.Context
	cancelCtx context.CancelFunc
	quitCh    chan struct{}
	initCh    chan struct{}

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

	// Wait for the gRPC server and all runtimes to terminate.
	go func() {
		defer close(w.quitCh)

		for _, rt := range w.runtimes {
			<-rt.Quit()
		}

		<-w.Grpc.Quit()
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

	w.Grpc.Stop()
	w.cancelCtx()
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

	w.Grpc.Cleanup()
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

// NewUnmanagedCommitteeNode creates a new common committee node that is not
// managed by this worker.
//
// Since the node is unmanaged the caller needs to ensure that the node will
// be properly terminated once started.
//
// Note that this does not instruct the storage backend to watch the given
// runtime.
func (w *Worker) NewUnmanagedCommitteeNode(runtime runtimeRegistry.Runtime, enableP2P bool) (*committee.Node, error) {
	var p2p *p2p.P2P
	if enableP2P {
		// Make sure that there is no other (managed) runtime already registered
		// with the same identifier as registering another will overwrite the
		// P2P handler.
		if w.runtimes[runtime.ID()] != nil {
			return nil, fmt.Errorf("worker/common: managed runtime with id %s already exists", runtime.ID())
		}
		p2p = w.P2P
	}

	return committee.NewNode(
		runtime,
		w.Identity,
		w.KeyManager,
		w.Consensus,
		p2p,
	)
}

func (w *Worker) registerRuntime(runtime runtimeRegistry.Runtime) error {
	id := runtime.ID()
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	node, err := w.NewUnmanagedCommitteeNode(runtime, true)
	if err != nil {
		return err
	}
	w.runtimes[id] = node

	w.logger.Info("new runtime registered",
		"runtime_id", id,
	)

	return nil
}

func newWorker(
	ctx context.Context,
	cancelCtx context.CancelFunc,
	dataDir string,
	enabled bool,
	identity *identity.Identity,
	consensus consensus.Backend,
	grpc *grpc.Server,
	grpcPolicyWatcher policyAPI.PolicyWatcher,
	p2p *p2p.P2P,
	ias ias.Endpoint,
	keyManager keymanagerApi.Backend,
	runtimeRegistry runtimeRegistry.Registry,
	cfg Config,
	genesisDoc *genesis.Document,
) (*Worker, error) {
	w := &Worker{
		enabled:           enabled,
		cfg:               cfg,
		DataDir:           dataDir,
		Identity:          identity,
		Consensus:         consensus,
		Grpc:              grpc,
		GrpcPolicyWatcher: grpcPolicyWatcher,
		P2P:               p2p,
		IAS:               ias,
		KeyManager:        keyManager,
		RuntimeRegistry:   runtimeRegistry,
		GenesisDoc:        genesisDoc,
		runtimes:          make(map[common.Namespace]*committee.Node),
		ctx:               ctx,
		cancelCtx:         cancelCtx,
		quitCh:            make(chan struct{}),
		initCh:            make(chan struct{}),
		logger:            logging.GetLogger("worker/common"),
	}

	if enabled {
		for _, rt := range runtimeRegistry.Runtimes() {
			// Register all configured runtimes.
			if err := w.registerRuntime(rt); err != nil {
				return nil, err
			}
		}
	}

	return w, nil
}

// New creates a new worker.
func New(
	dataDir string,
	enabled bool,
	identity *identity.Identity,
	consensus consensus.Backend,
	p2p *p2p.P2P,
	ias ias.Endpoint,
	keyManager keymanagerApi.Backend,
	runtimeRegistry runtimeRegistry.Registry,
	genesisDoc *genesis.Document,
) (*Worker, error) {
	cfg, err := NewConfig()
	if err != nil {
		return nil, fmt.Errorf("worker/common: failed to initialize config: %w", err)
	}

	// Create externally-accessible gRPC server.
	serverConfig := &grpc.ServerConfig{
		Name:     "external",
		Port:     cfg.ClientPort,
		Identity: identity,
	}
	grpc, err := grpc.NewServer(serverConfig)
	if err != nil {
		return nil, err
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	grpcPolicyWatcher := policywatcher.New(ctx, cfg.SentryAddresses, identity)

	return newWorker(
		ctx,
		cancelCtx,
		dataDir,
		enabled,
		identity,
		consensus,
		grpc,
		grpcPolicyWatcher,
		p2p,
		ias,
		keyManager,
		runtimeRegistry,
		*cfg,
		genesisDoc,
	)
}
