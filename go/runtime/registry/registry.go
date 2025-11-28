// Package registry provides a registry of runtimes supported by
// the running oasis-node. It serves as a central point of runtime
// configuration.
package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
	"github.com/oasisprotocol/oasis-core/go/runtime/log"
	"github.com/oasisprotocol/oasis-core/go/runtime/volume"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
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
	service.BackgroundService

	// GetRuntime returns the per-runtime interface.
	GetRuntime(runtimeID common.Namespace) (Runtime, error)

	// Runtimes returns a list of all runtimes.
	Runtimes() []Runtime

	// Indexer returns runtime history indexer for the specified runtime.
	Indexer(runtimeID common.Namespace) (*history.BlockIndexer, bool)

	// RegisterClient registers a runtime client service. If the service has already been registered
	// this method returns an error.
	RegisterClient(rc runtimeClient.RuntimeClient) error

	// Client returns the runtime client service if available.
	Client() (runtimeClient.RuntimeClient, error)

	// FinishInitialization finalizes setup for all runtimes.
	FinishInitialization() error

	// GetBundleRegistry returns the bundle registry.
	GetBundleRegistry() *bundle.Registry

	// GetBundleManager returns the bundle manager.
	GetBundleManager() *bundle.Manager

	// GetVolumeManager returns the volume manager.
	GetVolumeManager() *volume.Manager

	// GetLogManager returns the log manager.
	GetLogManager() *log.Manager
}

// Runtime is the running node's supported runtime interface.
type Runtime interface {
	// ID is the runtime identifier.
	ID() common.Namespace

	// DataDir returns the runtime-specific data directory.
	DataDir() string

	// IsManaged returns true iff the runtime is managed by the registry.
	IsManaged() bool

	// RegistryDescriptor waits for the runtime to be registered and
	// then returns its registry descriptor.
	RegistryDescriptor(ctx context.Context) (*registry.Runtime, error)

	// WatchRegistryDescriptor subscribes to registry descriptor updates.
	WatchRegistryDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error)

	// ActiveDescriptor waits for runtime to be initialized and then returns
	// currently active runtime descriptor.
	ActiveDescriptor(ctx context.Context) (*registry.Runtime, error)

	// WatchActiveDescriptor subscribes to runtime active descriptor updates.
	WatchActiveDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error)

	// RegisterStorage sets the given local storage backend for the runtime.
	RegisterStorage(storage storageAPI.Backend)

	// History returns the history for this runtime.
	History() history.History

	// Storage returns the per-runtime storage backend.
	Storage() storageAPI.Backend

	// LocalStorage returns the per-runtime local storage.
	LocalStorage() localstorage.LocalStorage
}

type runtime struct {
	sync.RWMutex
	startOne cmSync.One

	id                   common.Namespace
	dataDir              string
	registryDescriptor   *registry.Runtime
	activeDescriptor     *registry.Runtime
	activeDescriptorHash hash.Hash
	managed              bool

	consensus    consensus.Service
	storage      storageAPI.Backend
	localStorage localstorage.LocalStorage

	history history.History

	registryDescriptorCh       chan struct{}
	registryDescriptorNotifier *pubsub.Broker
	activeDescriptorCh         chan struct{}
	activeDescriptorNotifier   *pubsub.Broker

	bundleRegistry *bundle.Registry
	bundleManager  *bundle.Manager

	logger *logging.Logger
}

func newRuntime(
	runtimeID common.Namespace,
	managed bool,
	dataDir string,
	consensus consensus.Service,
	bundleRegistry *bundle.Registry,
	bundleManager *bundle.Manager,
) (*runtime, error) {
	logger := logging.GetLogger("runtime/registry").With("runtime_id", runtimeID)

	// Ensure runtime state directory exists.
	rtDataDir, err := runtimeConfig.EnsureRuntimeStateDir(dataDir, runtimeID)
	if err != nil {
		return nil, err
	}

	// Create runtime-specific local storage backend.
	localStorage, err := localstorage.New(rtDataDir, LocalStorageFile, runtimeID)
	if err != nil {
		return nil, fmt.Errorf("runtime/registry: cannot create local storage for runtime %s: %w", runtimeID, err)
	}

	return &runtime{
		startOne:                   cmSync.NewOne(),
		id:                         runtimeID,
		dataDir:                    rtDataDir,
		managed:                    managed,
		consensus:                  consensus,
		localStorage:               localStorage,
		registryDescriptorCh:       make(chan struct{}),
		registryDescriptorNotifier: pubsub.NewBroker(true),
		activeDescriptorCh:         make(chan struct{}),
		activeDescriptorNotifier:   pubsub.NewBroker(true),
		bundleRegistry:             bundleRegistry,
		bundleManager:              bundleManager,
		logger:                     logger,
	}, nil
}

// ID implements Runtime.
func (r *runtime) ID() common.Namespace {
	return r.id
}

// DataDir implements Runtime.
func (r *runtime) DataDir() string {
	return r.dataDir
}

// IsManaged implements Runtime.
func (r *runtime) IsManaged() bool {
	return r.managed
}

// RegistryDescriptor implements Runtime.
func (r *runtime) RegistryDescriptor(ctx context.Context) (*registry.Runtime, error) {
	// Wait for the descriptor to be ready.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.registryDescriptorCh:
	}

	r.RLock()
	d := r.registryDescriptor
	r.RUnlock()
	return d, nil
}

// ActiveDescriptor implements Runtime.
func (r *runtime) ActiveDescriptor(ctx context.Context) (*registry.Runtime, error) {
	// Wait for the descriptor to be ready.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.activeDescriptorCh:
	}

	r.RLock()
	d := r.activeDescriptor
	r.RUnlock()
	return d, nil
}

// WatchActiveDescriptor implements Runtime.
func (r *runtime) WatchActiveDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error) {
	sub := r.activeDescriptorNotifier.Subscribe()
	ch := make(chan *registry.Runtime)
	sub.Unwrap(ch)

	return ch, sub, nil
}

// WatchRegistryDescriptor implements Runtime.
func (r *runtime) WatchRegistryDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error) {
	sub := r.registryDescriptorNotifier.Subscribe()
	ch := make(chan *registry.Runtime)
	sub.Unwrap(ch)

	return ch, sub, nil
}

// RegisterStorage implements Runtime.
func (r *runtime) RegisterStorage(storage storageAPI.Backend) {
	r.Lock()
	defer r.Unlock()

	if r.storage != nil {
		panic("runtime storage backend already assigned")
	}
	r.storage = storage
}

// History implements Runtime.
func (r *runtime) History() history.History {
	return r.history
}

// Storage implements Runtime.
func (r *runtime) Storage() storageAPI.Backend {
	r.RLock()
	defer r.RUnlock()

	if r.storage == nil && r.managed {
		panic("runtime storage accessed before initialization")
	}
	return r.storage
}

// LocalStorage implements Runtime.
func (r *runtime) LocalStorage() localstorage.LocalStorage {
	return r.localStorage
}

// start starts the runtime worker.
func (r *runtime) start() {
	r.startOne.TryStart(r.run)
}

// stop halts the runtime worker.
func (r *runtime) stop() {
	r.startOne.TryStop()
	r.localStorage.Stop()
	if r.history != nil {
		r.history.Close()
	}
}

// cleanup cleans up the runtime worker.
func (r *runtime) cleanup() {
	if r.storage != nil {
		r.storage.Cleanup()
	}
}

func (r *runtime) run(ctx context.Context) {
	r.logger.Debug("waiting consensus sync")
	select {
	case <-ctx.Done():
		return
	case <-r.consensus.Synced():
	}
	r.logger.Debug("consensus synced")

	// Subscribe to epoch transitions.
	epoCh, sub, err := r.consensus.Beacon().WatchEpochs(ctx)
	if err != nil {
		r.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Subscribe to runtime updates.
	regCh, regSub, err := r.consensus.Registry().WatchRuntimes(ctx)
	if err != nil {
		r.logger.Error("failed to watch runtime updates",
			"err", err,
		)
		return
	}
	defer regSub.Close()

	var regInitialized, activeInitialized bool
	for {
		select {
		case <-ctx.Done():
			return
		case epoch := <-epoCh:
			if up := r.updateActiveDescriptor(ctx); up && !activeInitialized {
				close(r.activeDescriptorCh)
				activeInitialized = true
			}

			// Trigger clean-up for bundles less than active version.
			r.RLock()
			rt := r.activeDescriptor
			r.RUnlock()
			if rt == nil {
				continue
			}

			// Cleanup runtime bundles.
			active := rt.ActiveDeployment(epoch)
			if active == nil {
				continue
			}

			r.bundleManager.Cleanup(rt.ID, active.Version)
		case rt := <-regCh:
			if !rt.ID.Equal(&r.id) {
				continue
			}

			r.logger.Debug("updating registry runtime descriptor",
				"runtime", rt,
				"kind", rt.Kind,
			)

			r.Lock()
			r.registryDescriptor = rt
			r.Unlock()

			if !regInitialized {
				close(r.registryDescriptorCh)
				regInitialized = true
			}
			r.registryDescriptorNotifier.Broadcast(rt)

			// If this is a compute runtime and the active descriptor is not
			// initialized, update the active descriptor.
			if !activeInitialized && rt.IsCompute() {
				if up := r.updateActiveDescriptor(ctx); up && !activeInitialized {
					close(r.activeDescriptorCh)
					activeInitialized = true
				}
			}

			// Hot-load runtime bundles.
			now, err := r.consensus.Beacon().GetEpoch(ctx, consensus.HeightLatest)
			if err != nil {
				r.logger.Error("failed to get current epoch",
					"err", err,
				)
				continue
			}

			// Filter the manifest hash of the active version and all upcoming
			// versions.
			deployments := slices.Clone(rt.Deployments)
			sort.SliceStable(deployments, func(i, j int) bool {
				return deployments[i].Version.Less(deployments[j].Version)
			})

			var manifestHashes []hash.Hash
			for i := len(deployments) - 1; i >= 0; i-- {
				// Some deployments may lack a bundle manifest checksum,
				// as it is optional.
				if h := deployments[i].BundleChecksum; len(h) == hash.Size {
					manifestHashes = append(manifestHashes, hash.Hash(h))
				}

				// Stop at the active deployment since versions were sorted
				// and now follow chronological order.
				if deployments[i].ValidFrom <= now {
					break
				}
			}

			r.bundleManager.Download(r.id, manifestHashes)
		}
	}
}

func (r *runtime) updateActiveDescriptor(ctx context.Context) bool {
	state, err := r.consensus.RootHash().GetRuntimeState(ctx, &roothash.RuntimeRequest{
		RuntimeID: r.id,
		Height:    consensus.HeightLatest,
	})
	if err != nil {
		r.logger.Error("querying roothash state",
			"err", err,
		)
		return false
	}

	h := hash.NewFrom(state.Runtime)
	// This is only called from the `run` thread and `activeDescriptorHash`
	// is only mutated bellow, so no need for a lock here.
	if h.Equal(&r.activeDescriptorHash) {
		r.logger.Debug("active runtime descriptor didn't change",
			"runtime", state.Runtime,
			"hash", h,
		)
		return false
	}

	r.logger.Debug("updating active runtime descriptor",
		"runtime", state.Runtime,
		"hash", h,
	)
	r.Lock()
	r.activeDescriptor = state.Runtime
	r.activeDescriptorHash = h
	r.Unlock()

	r.activeDescriptorNotifier.Broadcast(state.Runtime)

	return true
}

func (r *runtime) finishInitialization() error {
	r.Lock()
	defer r.Unlock()

	if r.storage == nil && r.managed {
		return fmt.Errorf("runtime/registry: nobody provided a storage backend for runtime %s", r.id)
	}

	return nil
}

type runtimeRegistry struct {
	sync.RWMutex

	quitCh chan struct{}

	logger *logging.Logger

	dataDir string

	consensus consensus.Service
	client    runtimeClient.RuntimeClient

	runtimes map[common.Namespace]*runtime
	indexers map[common.Namespace]*history.BlockIndexer

	historyFactory history.Factory

	bundleRegistry *bundle.Registry
	bundleManager  *bundle.Manager
	volumeManager  *volume.Manager
	logManager     *log.Manager
}

// GetRuntime implements Registry.
func (r *runtimeRegistry) GetRuntime(runtimeID common.Namespace) (Runtime, error) {
	r.RLock()
	defer r.RUnlock()

	rt, ok := r.runtimes[runtimeID]
	if !ok {
		return nil, fmt.Errorf("runtime/registry: runtime %s not found", runtimeID)
	}
	return rt, nil
}

// Indexer implements Registry.
func (r *runtimeRegistry) Indexer(runtimeID common.Namespace) (*history.BlockIndexer, bool) {
	r.RLock()
	defer r.RUnlock()

	indexer, ok := r.indexers[runtimeID]
	return indexer, ok
}

// Runtimes implements Registry.
func (r *runtimeRegistry) Runtimes() []Runtime {
	r.RLock()
	defer r.RUnlock()

	rts := make([]Runtime, 0, len(r.runtimes))
	for _, rt := range r.runtimes {
		rts = append(rts, rt)
	}
	return rts
}

// createRuntime creates a new runtime that may or may not be managed
// by this registry.
func (r *runtimeRegistry) createRuntime(runtimeID common.Namespace, managed bool) (Runtime, error) {
	r.Lock()
	defer r.Unlock()

	r.logger.Info("adding runtime",
		"id", runtimeID,
		"managed", managed,
	)

	if len(r.runtimes) >= MaxRuntimeCount {
		return nil, fmt.Errorf("runtime/registry: too many registered runtimes")
	}

	if _, ok := r.runtimes[runtimeID]; ok {
		return nil, fmt.Errorf("runtime/registry: runtime already registered: %s", runtimeID)
	}

	rt, err := newRuntime(runtimeID, managed, r.dataDir, r.consensus, r.bundleRegistry, r.bundleManager)
	if err != nil {
		return nil, err
	}

	if managed {
		// Create runtime history keeper.
		rt.history, err = r.historyFactory(runtimeID, rt.dataDir)
		if err != nil {
			return nil, fmt.Errorf("runtime/registry: cannot create block history for runtime %s: %w", runtimeID, err)
		}

		// Register a consensus state prune handler to make sure that we don't
		// prune blocks that haven't yet been indexed by the roothash backend.
		r.consensus.Pruner().RegisterHandler(rt.history)

		// Start indexing blocks.
		indexer := history.NewBlockIndexer(r.consensus, rt.history, config.GlobalConfig.Runtime.Indexer.BatchSize)
		r.indexers[runtimeID] = indexer
	}

	r.runtimes[runtimeID] = rt

	r.logger.Info("runtime added",
		"id", runtimeID,
		"managed", managed,
	)

	return rt, nil
}

// RegisterClient implements Registry.
func (r *runtimeRegistry) RegisterClient(rc runtimeClient.RuntimeClient) error {
	r.Lock()
	defer r.Unlock()

	if r.client != nil {
		return fmt.Errorf("runtime/registry: client already registered for runtime")
	}
	r.client = rc
	return nil
}

// Client implements Registry.
func (r *runtimeRegistry) Client() (runtimeClient.RuntimeClient, error) {
	r.RLock()
	defer r.RUnlock()

	if r.client == nil {
		return nil, fmt.Errorf("runtime/registry: client not available for runtime")
	}
	return r.client, nil
}

// FinishInitialization implements Registry.
func (r *runtimeRegistry) FinishInitialization() error {
	r.RLock()
	defer r.RUnlock()

	for _, rt := range r.runtimes {
		if err := rt.finishInitialization(); err != nil {
			return err
		}
	}
	return nil
}

// GetBundleRegistry implements Registry.
func (r *runtimeRegistry) GetBundleRegistry() *bundle.Registry {
	return r.bundleRegistry
}

// GetBundleManager implements Registry.
func (r *runtimeRegistry) GetBundleManager() *bundle.Manager {
	return r.bundleManager
}

// GetVolumeManager implements Registry.
func (r *runtimeRegistry) GetVolumeManager() *volume.Manager {
	return r.volumeManager
}

// GetLogManager implements Registry.
func (r *runtimeRegistry) GetLogManager() *log.Manager {
	return r.logManager
}

// Name implements BackgroundService.
func (r *runtimeRegistry) Name() string {
	return "runtime registry"
}

// Start implements BackgroundService.
func (r *runtimeRegistry) Start() error {
	r.bundleManager.Start()
	r.volumeManager.Start()

	r.RLock()
	defer r.RUnlock()
	for _, rt := range r.runtimes {
		rt.start()
	}
	for _, indexer := range r.indexers {
		indexer.Start()
	}

	return nil
}

// Stop implements BackgroundService.
func (r *runtimeRegistry) Stop() {
	r.bundleManager.Stop()
	r.volumeManager.Stop()

	r.RLock()
	defer r.RUnlock()
	for _, rt := range r.runtimes {
		rt.stop()
	}
	for _, indexer := range r.indexers {
		indexer.Stop()
	}

	close(r.quitCh)
}

// Quit implements BackgroundService.
func (r *runtimeRegistry) Quit() <-chan struct{} {
	return r.quitCh
}

// Cleanup implements BackgroundService.
func (r *runtimeRegistry) Cleanup() {
	r.RLock()
	defer r.RUnlock()
	for _, rt := range r.runtimes {
		rt.cleanup()
	}
}

// Init initializes the runtime registry by adding runtimes from the global
// runtime configuration to the registry.
func (r *runtimeRegistry) Init(runtimeIDs []common.Namespace) error {
	managed := config.GlobalConfig.Mode != config.ModeKeyManager

	for _, runtimeID := range runtimeIDs {
		if _, err := r.createRuntime(runtimeID, managed); err != nil {
			r.logger.Error("failed to add runtime",
				"err", err,
				"id", runtimeID,
			)
			return fmt.Errorf("failed to add runtime %s: %w", runtimeID, err)
		}
	}

	return nil
}

// New creates a new runtime registry.
func New(
	dataDir string,
	consensus consensus.Service,
) (Registry, error) {
	// Get configured runtime IDs.
	runtimeIDs, err := GetConfiguredRuntimeIDs()
	if err != nil {
		return nil, err
	}

	// Create volume manager.
	volumeManager, err := volume.NewManager(dataDir)
	if err != nil {
		return nil, err
	}

	// Create bundle registry and discovery.
	bundleRegistry := bundle.NewRegistry()
	bundleManager, err := bundle.NewManager(dataDir, runtimeIDs, bundleRegistry, volumeManager)
	if err != nil {
		return nil, err
	}

	// Create log manager.
	logManager := log.NewManager(dataDir)

	// Create history keeper factory.
	historyFactory, err := createHistoryFactory()
	if err != nil {
		return nil, err
	}

	// Create runtime registry.
	r := &runtimeRegistry{
		logger:         logging.GetLogger("runtime/registry"),
		quitCh:         make(chan struct{}),
		dataDir:        dataDir,
		consensus:      consensus,
		runtimes:       make(map[common.Namespace]*runtime),
		indexers:       make(map[common.Namespace]*history.BlockIndexer),
		historyFactory: historyFactory,
		bundleRegistry: bundleRegistry,
		bundleManager:  bundleManager,
		volumeManager:  volumeManager,
		logManager:     logManager,
	}

	// Initialize the runtime registry.
	if err = r.Init(runtimeIDs); err != nil {
		return nil, err
	}

	return r, nil
}
