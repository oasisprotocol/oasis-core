// Package registry provides a registry of runtimes supported by
// the running oasis-node. It serves as a central point of runtime
// configuration.
package registry

import (
	"context"
	"fmt"
	"sync"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
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
	GetRuntime(runtimeID signature.PublicKey) (Runtime, error)

	// Runtimes returns a list of all supported runtimes.
	Runtimes() []Runtime

	// NewUnmanagedRuntime creates a new runtime that is not managed by this
	// registry.
	NewUnmanagedRuntime(runtimeID signature.PublicKey) Runtime

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
	ID() signature.PublicKey

	// RegistryDescriptor waits for the runtime to be registered and
	// then returns its registry descriptor.
	RegistryDescriptor(ctx context.Context) (*registry.Runtime, error)

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
	id         signature.PublicKey
	descriptor *registry.Runtime

	consensus    consensus.Backend
	storage      storageAPI.Backend
	localStorage localstorage.LocalStorage

	history    history.History
	tagIndexer *tagindexer.Service
}

func (r *runtime) ID() signature.PublicKey {
	return r.id
}

func (r *runtime) RegistryDescriptor(ctx context.Context) (*registry.Runtime, error) {
	if r.descriptor != nil {
		return r.descriptor, nil
	}

	ch, sub, err := r.consensus.Registry().WatchRuntimes(ctx)
	if err != nil {
		return nil, err
	}
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case rt := <-ch:
			if rt.ID.Equal(r.id) {
				r.descriptor = rt
				return rt, nil
			}
		}
	}
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

type runtimeRegistry struct {
	sync.RWMutex

	logger *logging.Logger

	dataDir   string
	consensus consensus.Backend
	identity  *identity.Identity

	runtimes map[signature.PublicKey]*runtime
}

func (r *runtimeRegistry) GetRuntime(runtimeID signature.PublicKey) (Runtime, error) {
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

func (r *runtimeRegistry) NewUnmanagedRuntime(runtimeID signature.PublicKey) Runtime {
	return &runtime{
		id:        runtimeID,
		history:   history.NewNop(runtimeID),
		consensus: r.consensus,
	}
}

func (r *runtimeRegistry) StorageRouter() storageAPI.Backend {
	return &storageRouter{registry: r}
}

func (r *runtimeRegistry) Cleanup() {
	r.Lock()
	defer r.Unlock()

	for _, rt := range r.runtimes {
		// Close local storage backend.
		rt.localStorage.Stop()
		// Close storage backend.
		rt.storage.Cleanup()
		// Close tag indexer service.
		rt.tagIndexer.Stop()
		<-rt.tagIndexer.Quit()
		// Close history keeper.
		rt.history.Close()
	}
}

func (r *runtimeRegistry) addSupportedRuntime(ctx context.Context, id signature.PublicKey, cfg *RuntimeConfig) error {
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
	// TODO: Pass runtime identifier.
	storageBackend, err := storage.New(ctx, path, r.identity, r.consensus.Scheduler(), r.consensus.Registry())
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

	// If using a storage client, it should watch the configured runtimes.
	// TODO: This should be done automatically by the storage backend when we add a runtime parameter.
	if storageClient, ok := storageBackend.(storageAPI.ClientBackend); ok {
		if err = storageClient.WatchRuntime(id); err != nil {
			r.logger.Warn("error watching storage runtime, expected if using metricswrapper with local backend",
				"err", err,
			)
		}
	} else {
		r.logger.Info("not watching storage runtime since not using a storage client backend")
	}

	r.runtimes[id] = &runtime{
		id:           id,
		consensus:    r.consensus,
		storage:      storageBackend,
		localStorage: localStorage,
		history:      history,
		tagIndexer:   tagIndexer,
	}

	// Start tracking this runtime.
	if err = r.consensus.RootHash().TrackRuntime(ctx, history); err != nil {
		return fmt.Errorf("runtime/registry: cannot track runtime %s: %w", id, err)
	}

	return nil
}

// New creates a new runtime registry.
func New(ctx context.Context, dataDir string, consensus consensus.Backend, identity *identity.Identity) (Registry, error) {
	r := &runtimeRegistry{
		logger:    logging.GetLogger("runtime/registry"),
		dataDir:   dataDir,
		consensus: consensus,
		identity:  identity,
		runtimes:  make(map[signature.PublicKey]*runtime),
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
