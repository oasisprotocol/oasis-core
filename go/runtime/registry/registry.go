// Package registry provides a registry of runtimes supported by
// the running oasis-node. It serves as a central point of runtime
// configuration.
package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	runtimeHost "github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
	"github.com/oasisprotocol/oasis-core/go/runtime/tagindexer"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/client"
)

const (
	// MaxRuntimeCount is the maximum number of runtimes that can be supported
	// by a single node.
	MaxRuntimeCount = 64

	// LocalStorageFile is the filename of the worker's local storage database.
	LocalStorageFile = "worker-local-storage.badger.db"
)

// ErrRuntimeHostNotConfigured is the error returned when the runtime host is not configured for a
// specified runtime and a request is made to get the runtime host provisioner.
var ErrRuntimeHostNotConfigured = errors.New("runtime/registry: runtime host not configured")

// Registry is the running node's runtime registry interface.
type Registry interface {
	// GetRuntime returns the per-runtime interface if the runtime is supported.
	GetRuntime(runtimeID common.Namespace) (Runtime, error)

	// Runtimes returns a list of all supported runtimes.
	Runtimes() []Runtime

	// NewUnmanagedRuntime creates a new runtime that is not managed by this
	// registry.
	NewUnmanagedRuntime(ctx context.Context, runtimeID common.Namespace) (Runtime, error)

	// StorageRouter returns a storage backend which routes requests to the
	// correct per-runtime storage backend based on the namespace contained
	// in the request.
	StorageRouter() storageAPI.Backend

	// Cleanup performs post-termination cleanup.
	Cleanup()

	// FinishInitialization finalizes setup for all runtimes and starts their
	// tag indexers.
	FinishInitialization(ctx context.Context) error
}

// Runtime is the running node's supported runtime interface.
type Runtime interface {
	// ID is the runtime identifier.
	ID() common.Namespace

	// RegistryDescriptor waits for the runtime to be registered and
	// then returns its registry descriptor.
	RegistryDescriptor(ctx context.Context) (*registry.Runtime, error)

	// WatchRegistryDescriptor subscribes to registry descriptor updates.
	WatchRegistryDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error)

	// RegisterStorage sets the given local storage backend for the runtime.
	RegisterStorage(storage storageAPI.Backend)

	// History returns the history for this runtime.
	History() history.History

	// TagIndexer returns the tag indexer backend.
	TagIndexer() tagindexer.QueryableBackend

	// Storage returns the per-runtime storage backend.
	Storage() storageAPI.Backend

	// LocalStorage returns the per-runtime local storage.
	LocalStorage() localstorage.LocalStorage

	// Host returns the runtime host configuration and provisioner if configured.
	Host(ctx context.Context) (runtimeHost.Config, runtimeHost.Provisioner, error)
}

type runtime struct {
	sync.RWMutex

	id         common.Namespace
	descriptor *registry.Runtime

	consensus    consensus.Backend
	storage      storageAPI.Backend
	localStorage localstorage.LocalStorage

	history        history.History
	tagIndexer     *tagindexer.Service
	indexerStarted bool

	cancelCtx          context.CancelFunc
	descriptorCh       chan struct{}
	descriptorNotifier *pubsub.Broker

	hostProvisioners map[node.TEEHardware]runtimeHost.Provisioner
	hostConfig       *runtimeHost.Config

	logger *logging.Logger
}

func (r *runtime) ID() common.Namespace {
	return r.id
}

func (r *runtime) RegistryDescriptor(ctx context.Context) (*registry.Runtime, error) {
	// Wait for the descriptor to be ready.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.descriptorCh:
	}

	r.RLock()
	d := r.descriptor
	r.RUnlock()
	return d, nil
}

func (r *runtime) WatchRegistryDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error) {
	sub := r.descriptorNotifier.Subscribe()
	ch := make(chan *registry.Runtime)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *runtime) RegisterStorage(storage storageAPI.Backend) {
	r.Lock()
	defer r.Unlock()

	if r.storage != nil {
		panic("runtime storage backend already assigned")
	}
	r.storage = storage
}

func (r *runtime) History() history.History {
	return r.history
}

func (r *runtime) TagIndexer() tagindexer.QueryableBackend {
	return r.tagIndexer
}

func (r *runtime) Storage() storageAPI.Backend {
	r.RLock()
	defer r.RUnlock()

	if r.storage == nil {
		panic("runtime storage accessed before initialization")
	}
	return r.storage
}

func (r *runtime) LocalStorage() localstorage.LocalStorage {
	return r.localStorage
}

func (r *runtime) Host(ctx context.Context) (runtimeHost.Config, runtimeHost.Provisioner, error) {
	if r.hostProvisioners == nil || r.hostConfig == nil {
		return runtimeHost.Config{}, nil, ErrRuntimeHostNotConfigured
	}

	rt, err := r.RegistryDescriptor(ctx)
	if err != nil {
		return runtimeHost.Config{}, nil, fmt.Errorf("failed to get runtime registry descriptor: %w", err)
	}

	provisioner, ok := r.hostProvisioners[rt.TEEHardware]
	if !ok {
		return runtimeHost.Config{}, nil, fmt.Errorf("no provisioner suitable for TEE hardware '%s'", rt.TEEHardware)
	}

	return *r.hostConfig, provisioner, nil
}

func (r *runtime) stop() {
	// Stop watching runtime updates.
	r.cancelCtx()
	// Close local storage backend.
	r.localStorage.Stop()
	// Close storage backend.
	if r.storage != nil {
		r.storage.Cleanup()
	}
	// Close tag indexer service.
	if r.tagIndexer != nil && r.indexerStarted {
		r.tagIndexer.Stop()
		<-r.tagIndexer.Quit()
	}
	// Close history keeper.
	r.history.Close()
}

func (r *runtime) watchUpdates(ctx context.Context, ch <-chan *registry.Runtime, sub pubsub.ClosableSubscription) {
	defer sub.Close()

	var initialized bool
	for {
		select {
		case <-ctx.Done():
			return
		case rt := <-ch:
			if !rt.ID.Equal(&r.id) {
				continue
			}

			r.logger.Debug("updated runtime descriptor",
				"runtime", rt,
			)

			r.Lock()
			r.descriptor = rt
			r.Unlock()

			if !initialized {
				close(r.descriptorCh)
				initialized = true
			}

			r.descriptorNotifier.Broadcast(rt)
		}
	}
}

func (r *runtime) finishInitialization(ctx context.Context, ident *identity.Identity) error {
	r.Lock()
	defer r.Unlock()

	if r.storage == nil {
		storageBackend, err := client.New(ctx, r.id, ident, r.consensus.Scheduler(), r.consensus.Registry(), r)
		if err != nil {
			return fmt.Errorf("runtime/registry: cannot create storage for runtime %s: %w", r.id, err)
		}
		r.storage = storageBackend
	}

	if err := r.tagIndexer.Start(r.storage); err != nil {
		return fmt.Errorf("runtime/registry: cannot start tag indexer for runtime %s: %w", r.id, err)
	}
	r.indexerStarted = true

	return nil
}

type runtimeRegistry struct {
	sync.RWMutex

	logger *logging.Logger

	dataDir string
	cfg     *RuntimeConfig

	consensus consensus.Backend
	identity  *identity.Identity

	runtimes map[common.Namespace]*runtime
}

func (r *runtimeRegistry) GetRuntime(runtimeID common.Namespace) (Runtime, error) {
	r.RLock()
	defer r.RUnlock()

	rt := r.runtimes[runtimeID]
	if rt == nil {
		return nil, fmt.Errorf("runtime/registry: runtime %s is not supported", runtimeID)
	}
	return rt, nil
}

func (r *runtimeRegistry) Runtimes() []Runtime {
	r.RLock()
	defer r.RUnlock()

	var rts []Runtime
	for _, rt := range r.runtimes {
		rts = append(rts, rt)
	}
	return rts
}

func (r *runtimeRegistry) NewUnmanagedRuntime(ctx context.Context, runtimeID common.Namespace) (Runtime, error) {
	return newRuntime(ctx, runtimeID, r.cfg, r.consensus, r.logger)
}

func (r *runtimeRegistry) StorageRouter() storageAPI.Backend {
	return &storageRouter{registry: r}
}

func (r *runtimeRegistry) Cleanup() {
	r.Lock()
	defer r.Unlock()

	for _, rt := range r.runtimes {
		rt.stop()
	}
}

func (r *runtimeRegistry) FinishInitialization(ctx context.Context) error {
	r.RLock()
	defer r.RUnlock()

	for _, rt := range r.runtimes {
		if err := rt.finishInitialization(ctx, r.identity); err != nil {
			return err
		}
	}
	return nil
}

func (r *runtimeRegistry) addSupportedRuntime(ctx context.Context, id common.Namespace) (rerr error) {
	r.Lock()
	defer r.Unlock()

	if len(r.runtimes) >= MaxRuntimeCount {
		return fmt.Errorf("runtime/registry: too many registered runtimes")
	}

	if _, ok := r.runtimes[id]; ok {
		return fmt.Errorf("runtime/registry: runtime already registered: %s", id)
	}

	path, err := EnsureRuntimeStateDir(r.dataDir, id)
	if err != nil {
		return err
	}

	rt, err := newRuntime(ctx, id, r.cfg, r.consensus, r.logger)
	if err != nil {
		return err
	}

	// Create runtime history keeper.
	history, err := history.New(path, id, &r.cfg.History)
	if err != nil {
		return fmt.Errorf("runtime/registry: cannot create block history for runtime %s: %w", id, err)
	}
	defer func() {
		if rerr != nil {
			history.Close()
		}
	}()

	// Create runtime-specific local storage backend.
	localStorage, err := localstorage.New(path, LocalStorageFile, id)
	if err != nil {
		return fmt.Errorf("runtime/registry: cannot create local storage for runtime %s: %w", id, err)
	}
	defer func() {
		if rerr != nil {
			localStorage.Stop()
		}
	}()

	// Create runtime-specific storage backend.
	var ns common.Namespace
	copy(ns[:], id[:])

	// Create runtime tag indexer (to be started later).
	tagIndexer, err := tagindexer.New(path, r.cfg.TagIndexer, history, r.consensus.RootHash())
	if err != nil {
		return fmt.Errorf("runtime/registry: cannot create tag indexer for runtime %s: %w", id, err)
	}

	// Start tracking this runtime.
	if err = r.consensus.RootHash().TrackRuntime(ctx, history); err != nil {
		return fmt.Errorf("runtime/registry: cannot track runtime %s: %w", id, err)
	}

	rt.localStorage = localStorage
	rt.history = history
	rt.tagIndexer = tagIndexer
	r.runtimes[id] = rt

	return nil
}

func newRuntime(
	ctx context.Context,
	id common.Namespace,
	cfg *RuntimeConfig,
	consensus consensus.Backend,
	logger *logging.Logger,
) (*runtime, error) {
	// Start watching this runtime's descriptor.
	ch, sub, err := consensus.Registry().WatchRuntimes(ctx)
	if err != nil {
		return nil, fmt.Errorf("runtime/registry: failed to watch updates for runtime %s: %w", id, err)
	}
	watchCtx, cancel := context.WithCancel(ctx)

	rt := &runtime{
		id:                 id,
		consensus:          consensus,
		cancelCtx:          cancel,
		descriptorCh:       make(chan struct{}),
		descriptorNotifier: pubsub.NewBroker(true),
		logger:             logger.With("runtime_id", id),
	}
	go rt.watchUpdates(watchCtx, ch, sub)

	// Configure runtime host if needed.
	if cfg.Host != nil {
		rt.hostProvisioners = cfg.Host.Provisioners
		rt.hostConfig = cfg.Host.Runtimes[id]
	}

	return rt, nil
}

// New creates a new runtime registry.
func New(ctx context.Context, dataDir string, consensus consensus.Backend, identity *identity.Identity, ias ias.Endpoint) (Registry, error) {
	cfg, err := newConfig(consensus, ias)
	if err != nil {
		return nil, err
	}

	r := &runtimeRegistry{
		logger:    logging.GetLogger("runtime/registry"),
		dataDir:   dataDir,
		cfg:       cfg,
		consensus: consensus,
		identity:  identity,
		runtimes:  make(map[common.Namespace]*runtime),
	}

	runtimes, err := ParseRuntimeMap(viper.GetStringSlice(CfgSupported))
	if err != nil {
		return nil, err
	}
	for id := range runtimes {
		r.logger.Info("adding supported runtime",
			"id", id,
		)

		if err := r.addSupportedRuntime(ctx, id); err != nil {
			r.logger.Error("failed to add supported runtime",
				"err", err,
				"id", id,
			)
			return nil, fmt.Errorf("failed to add runtime %s: %w", id, err)
		}
	}

	if len(runtimes) == 0 {
		r.logger.Info("no supported runtimes configured")
	}

	return r, nil
}
