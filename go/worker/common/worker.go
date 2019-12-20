package common

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	ias "github.com/oasislabs/oasis-core/go/ias/api"
	keymanagerApi "github.com/oasislabs/oasis-core/go/keymanager/api"
	keymanagerClient "github.com/oasislabs/oasis-core/go/keymanager/client"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/common/host"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
)

// LocalStorageFile is the filename of the worker's local storage database.
const LocalStorageFile = "worker-local-storage.badger.db"

// Worker is a garbage bag with lower level services and common runtime objects.
type Worker struct {
	enabled bool
	cfg     Config

	Identity         *identity.Identity
	Roothash         roothash.Backend
	Registry         registry.Backend
	Scheduler        scheduler.Backend
	Consensus        consensus.Backend
	Grpc             *grpc.Server
	P2P              *p2p.P2P
	IAS              ias.Endpoint
	KeyManager       keymanagerApi.Backend
	KeyManagerClient *keymanagerClient.Client
	LocalStorage     *host.LocalStorage
	RuntimeRegistry  runtimeRegistry.Registry
	GenesisDoc       *genesis.Document

	runtimes map[signature.PublicKey]*committee.Node

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

	if w.LocalStorage != nil {
		w.LocalStorage.Stop()
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

// GetRuntimes returns a map of registered runtimes.
func (w *Worker) GetRuntimes() map[signature.PublicKey]*committee.Node {
	return w.runtimes
}

// GetRuntime returns a registered runtime.
//
// In case the runtime with the specified id was not registered it
// returns nil.
func (w *Worker) GetRuntime(id signature.PublicKey) *committee.Node {
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
		w.KeyManagerClient,
		w.LocalStorage,
		w.Roothash,
		w.Registry,
		w.Scheduler,
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
	dataDir string,
	enabled bool,
	identity *identity.Identity,
	roothash roothash.Backend,
	registryInst registry.Backend,
	scheduler scheduler.Backend,
	consensus consensus.Backend,
	grpc *grpc.Server,
	p2p *p2p.P2P,
	ias ias.Endpoint,
	keyManager keymanagerApi.Backend,
	keyManagerClient *keymanagerClient.Client,
	runtimeRegistry runtimeRegistry.Registry,
	cfg Config,
	genesisDoc *genesis.Document,
) (*Worker, error) {
	w := &Worker{
		enabled:          enabled,
		cfg:              cfg,
		Identity:         identity,
		Roothash:         roothash,
		Registry:         registryInst,
		Scheduler:        scheduler,
		Consensus:        consensus,
		Grpc:             grpc,
		P2P:              p2p,
		IAS:              ias,
		KeyManager:       keyManager,
		KeyManagerClient: keyManagerClient,
		RuntimeRegistry:  runtimeRegistry,
		GenesisDoc:       genesisDoc,
		runtimes:         make(map[signature.PublicKey]*committee.Node),
		quitCh:           make(chan struct{}),
		initCh:           make(chan struct{}),
		logger:           logging.GetLogger("worker/common"),
	}

	if enabled {
		// Open the local storage.
		var err error
		if w.LocalStorage, err = host.NewLocalStorage(dataDir, LocalStorageFile); err != nil {
			w.logger.Error("failed to initialize local storage",
				"err", err,
				"data_dir", dataDir,
				"local_storage_file", LocalStorageFile,
			)
			return nil, err
		}

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
	roothash roothash.Backend,
	registry registry.Backend,
	scheduler scheduler.Backend,
	consensus consensus.Backend,
	p2p *p2p.P2P,
	ias ias.Endpoint,
	keyManager keymanagerApi.Backend,
	keyManagerClient *keymanagerClient.Client,
	runtimeRegistry runtimeRegistry.Registry,
	genesisDoc *genesis.Document,
) (*Worker, error) {
	cfg, err := newConfig()
	if err != nil {
		return nil, fmt.Errorf("worker/common: failed to initialize config: %w", err)
	}

	// Create externally-accessible gRPC server.
	serverConfig := &grpc.ServerConfig{
		Name:        "external",
		Port:        cfg.ClientPort,
		Certificate: identity.TLSCertificate,
	}
	grpc, err := grpc.NewServer(serverConfig)
	if err != nil {
		return nil, err
	}

	return newWorker(
		dataDir,
		enabled,
		identity,
		roothash,
		registry,
		scheduler,
		consensus,
		grpc,
		p2p,
		ias,
		keyManager,
		keyManagerClient,
		runtimeRegistry,
		*cfg,
		genesisDoc,
	)
}
