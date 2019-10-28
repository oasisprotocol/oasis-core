package common

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/consensus"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/version"
	"github.com/oasislabs/oasis-core/go/ias"
	keymanagerApi "github.com/oasislabs/oasis-core/go/keymanager/api"
	keymanagerClient "github.com/oasislabs/oasis-core/go/keymanager/client"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/common/host"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
)

// LocalStorageFile is the filename of the worker's local storage database.
const LocalStorageFile = "worker-local-storage.bolt.db"

// Runtime is a single runtime.
type Runtime struct {
	id      signature.PublicKey
	version version.Version

	node *committee.Node
}

// GetNode returns the committee node for this runtime.
func (r *Runtime) GetNode() *committee.Node {
	if r == nil {
		return nil
	}
	return r.node
}

// GetID returns the ID of this runtime.
func (r *Runtime) GetID() signature.PublicKey {
	return r.id
}

// Worker is a garbage bag with lower level services and common runtime objects.
type Worker struct {
	enabled bool
	cfg     Config

	Identity         *identity.Identity
	Storage          storage.Backend
	Roothash         roothash.Backend
	Registry         registry.Backend
	Scheduler        scheduler.Backend
	Consensus        consensus.Backend
	Grpc             *grpc.Server
	P2P              *p2p.P2P
	IAS              *ias.IAS
	KeyManager       keymanagerApi.Backend
	KeyManagerClient *keymanagerClient.Client
	LocalStorage     *host.LocalStorage

	runtimes map[signature.MapKey]*Runtime

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
			<-rt.node.Quit()
		}

		<-w.Grpc.Quit()
	}()

	// Wait for all runtimes to be initialized.
	go func() {
		for _, rt := range w.runtimes {
			<-rt.node.Initialized()
		}

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
		rt.node.Cleanup()
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
func (w *Worker) GetRuntimes() map[signature.MapKey]*Runtime {
	return w.runtimes
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

// NewUnmanagedCommitteeNode creates a new common committee node that is not
// managed by this worker.
//
// Since the node is unmanaged the caller needs to ensure that the node will
// be properly terminated once started.
//
// Note that this does not instruct the storage backend to watch the given
// runtime.
func (w *Worker) NewUnmanagedCommitteeNode(id signature.PublicKey, enableP2P bool) (*committee.Node, error) {
	var p2p *p2p.P2P
	if enableP2P {
		// Make sure that there is no other (managed) runtime already registered
		// with the same identifier as registering another will overwrite the
		// P2P handler.
		if w.runtimes[id.ToMapKey()] != nil {
			return nil, fmt.Errorf("worker/common: managed runtime with id %s already exists", id)
		}
		p2p = w.P2P
	}

	return committee.NewNode(
		id,
		w.Identity,
		w.KeyManager,
		w.KeyManagerClient,
		w.LocalStorage,
		w.Storage,
		w.Roothash,
		w.Registry,
		w.Scheduler,
		w.Consensus,
		p2p,
	)
}

func (w *Worker) registerRuntime(id signature.PublicKey) error {
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	node, err := w.NewUnmanagedCommitteeNode(id, true)
	if err != nil {
		return err
	}

	rt := &Runtime{
		id:      id,
		version: version.Version{Major: 0, Minor: 0, Patch: 0}, // Version is populated once the runtime has been loaded. -Matevz
		node:    node,
	}
	w.runtimes[rt.id.ToMapKey()] = rt

	w.logger.Info("new runtime registered",
		"runtime_id", rt.id,
	)

	// If using a storage client, it should watch the configured runtimes.
	if storageClient, ok := w.Storage.(storage.ClientBackend); ok {
		if err := storageClient.WatchRuntime(id); err != nil {
			w.logger.Warn("common/worker: error watching storage runtime",
				"err", err,
				"runtime_id", id,
			)
		}
	} else {
		w.logger.Info("not watching storage runtime since not using a storage client backend",
			"runtime_id", id,
		)
	}

	return nil
}

func newWorker(
	dataDir string,
	enabled bool,
	identity *identity.Identity,
	storageBackend storage.Backend,
	roothash roothash.Backend,
	registryInst registry.Backend,
	scheduler scheduler.Backend,
	consensus consensus.Backend,
	grpc *grpc.Server,
	p2p *p2p.P2P,
	ias *ias.IAS,
	keyManager keymanagerApi.Backend,
	keyManagerClient *keymanagerClient.Client,
	cfg Config,
) (*Worker, error) {
	w := &Worker{
		enabled:          enabled,
		cfg:              cfg,
		Identity:         identity,
		Storage:          storageBackend,
		Roothash:         roothash,
		Registry:         registryInst,
		Scheduler:        scheduler,
		Consensus:        consensus,
		Grpc:             grpc,
		P2P:              p2p,
		IAS:              ias,
		KeyManager:       keyManager,
		KeyManagerClient: keyManagerClient,
		runtimes:         make(map[signature.MapKey]*Runtime),
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

		for _, id := range cfg.Runtimes {
			// Register all configured runtimes.
			if err := w.registerRuntime(id); err != nil {
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
	storage storage.Backend,
	roothash roothash.Backend,
	registry registry.Backend,
	scheduler scheduler.Backend,
	consensus consensus.Backend,
	p2p *p2p.P2P,
	ias *ias.IAS,
	keyManager keymanagerApi.Backend,
	keyManagerClient *keymanagerClient.Client,
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

	return newWorker(dataDir, enabled, identity, storage, roothash, registry, scheduler, consensus, grpc, p2p, ias, keyManager, keyManagerClient, *cfg)
}
