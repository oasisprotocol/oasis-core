// Package registry provides a registry of runtimes supported by
// the running oasis-node. It serves as a central point of runtime
// configuration.
package registry

import (
	"context"
	"fmt"
	"sync"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/runtime/history"
	"github.com/oasislabs/oasis-core/go/runtime/localstorage"
	"github.com/oasislabs/oasis-core/go/runtime/tagindexer"
	"github.com/oasislabs/oasis-core/go/storage"
	storageAPI "github.com/oasislabs/oasis-core/go/storage/api"
)

const (
	// MaxRuntimeCount is the maximum number of runtimes that can be supported
	// by a single node.
	MaxRuntimeCount = 64

	// LocalStorageFile is the filename of the worker's local storage database.
	LocalStorageFile = "worker-local-storage.badger.db"
)

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

	// History returns the history for this runtime.
	History() history.History

	// TagIndexer returns the tag indexer backend.
	TagIndexer() tagindexer.QueryableBackend

	// Storage returns the per-runtime storage backend.
	Storage() storageAPI.Backend

	// LocalStorage returns the per-runtime local storage.
	LocalStorage() localstorage.LocalStorage
}

type runtime struct {
	sync.RWMutex

	id         common.Namespace
	descriptor *registry.Runtime

	consensus    consensus.Backend
	storage      storageAPI.Backend
	localStorage localstorage.LocalStorage

	history    history.History
	tagIndexer *tagindexer.Service

	cancelCtx          context.CancelFunc
	descriptorCh       chan struct{}
	descriptorNotifier *pubsub.Broker

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

func (r *runtime) History() history.History {
	return r.history
}

func (r *runtime) TagIndexer() tagindexer.QueryableBackend {
	return r.tagIndexer
}

func (r *runtime) Storage() storageAPI.Backend {
	return r.storage
}

func (r *runtime) LocalStorage() localstorage.LocalStorage {
	return r.localStorage
}

func (r *runtime) stop() {
	// Stop watching runtime updates.
	r.cancelCtx()
	// Close local storage backend.
	r.localStorage.Stop()
	// Close storage backend.
	r.storage.Cleanup()
	// Close tag indexer service.
	r.tagIndexer.Stop()
	<-r.tagIndexer.Quit()
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

type runtimeRegistry struct {
	sync.RWMutex

	logger *logging.Logger

	dataDir   string
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
	return newRuntime(ctx, runtimeID, r.consensus, r.logger)
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

func (r *runtimeRegistry) addSupportedRuntime(ctx context.Context, id common.Namespace, cfg *RuntimeConfig) error {
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

	// Create runtime history keeper.
	history, err := history.New(path, id, &cfg.History)
	if err != nil {
		return fmt.Errorf("runtime/registry: cannot create block history for runtime %s: %w", id, err)
	}

	// Create runtime-specific local storage backend.
	localStorage, err := localstorage.New(path, LocalStorageFile, id)
	if err != nil {
		return fmt.Errorf("runtime/registry: cannot create local storage for runtime %s: %w", id, err)
	}

	// Create runtime-specific storage backend.
	var ns common.Namespace
	copy(ns[:], id[:])

	storageBackend, err := storage.New(ctx, path, ns, r.identity, r.consensus.Scheduler(), r.consensus.Registry())
	if err != nil {
		return fmt.Errorf("runtime/registry: cannot create storage for runtime %s: %w", id, err)
	}

	// Create runtime tag indexer.
	tagIndexer, err := tagindexer.New(path, cfg.TagIndexer, history, r.consensus.RootHash(), storageBackend)
	if err != nil {
		return fmt.Errorf("runtime/registry: cannot create tag indexer for runtime %s: %w", id, err)
	}
	if err = tagIndexer.Start(); err != nil {
		return fmt.Errorf("runtime/registry: failed to start tag indexer for runtime %s: %w", id, err)
	}

	// Start tracking this runtime.
	if err = r.consensus.RootHash().TrackRuntime(ctx, history); err != nil {
		return fmt.Errorf("runtime/registry: cannot track runtime %s: %w", id, err)
	}

	rt, err := newRuntime(ctx, id, r.consensus, r.logger)
	if err != nil {
		return err
	}

	rt.storage = storageBackend
	rt.localStorage = localStorage
	rt.history = history
	rt.tagIndexer = tagIndexer
	r.runtimes[id] = rt

	return nil
}

func newRuntime(ctx context.Context, id common.Namespace, consensus consensus.Backend, logger *logging.Logger) (*runtime, error) {
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

	return rt, nil
}

// New creates a new runtime registry.
func New(ctx context.Context, dataDir string, consensus consensus.Backend, identity *identity.Identity) (Registry, error) {
	r := &runtimeRegistry{
		logger:    logging.GetLogger("runtime/registry"),
		dataDir:   dataDir,
		consensus: consensus,
		identity:  identity,
		runtimes:  make(map[common.Namespace]*runtime),
	}

	cfg, err := newConfig()
	if err != nil {
		return nil, err
	}

	runtimes, err := ParseRuntimeMap(viper.GetStringSlice(CfgSupported))
	if err != nil {
		return nil, err
	}
	for id := range runtimes {
		r.logger.Info("adding supported runtime",
			"id", id,
		)

		if err := r.addSupportedRuntime(ctx, id, cfg); err != nil {
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
