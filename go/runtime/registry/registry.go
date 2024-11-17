// Package registry provides a registry of runtimes supported by
// the running oasis-node. It serves as a central point of runtime
// configuration.
package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	runtimeHost "github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
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
	// GetRuntime returns the per-runtime interface if the runtime is managed.
	GetRuntime(runtimeID common.Namespace) (Runtime, error)

	// Runtimes returns a list of all managed runtimes.
	Runtimes() []Runtime

	// NewRuntime creates a new runtime that may or may not be managed
	// by this registry.
	NewRuntime(ctx context.Context, runtimeID common.Namespace, managed bool) (Runtime, error)

	// RegisterClient registers a runtime client service. If the service has already been registered
	// this method returns an error.
	RegisterClient(rc runtimeClient.RuntimeClient) error

	// Client returns the runtime client service if available.
	Client() (runtimeClient.RuntimeClient, error)

	// Cleanup performs post-termination cleanup.
	Cleanup()

	// FinishInitialization finalizes setup for all runtimes.
	FinishInitialization() error
}

// Runtime is the running node's supported runtime interface.
type Runtime interface {
	// ID is the runtime identifier.
	ID() common.Namespace

	// DataDir returns the runtime-specific data directory.
	DataDir() string

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

	// HostConfig returns the runtime host configuration for the given version
	// when available. Otherwise returns nil.
	HostConfig(version version.Version) *runtimeHost.Config

	// HostProvisioner returns the runtime host provisioner when available. Otherwise returns nil.
	HostProvisioner() runtimeHost.Provisioner

	// HostVersions returns a list of supported runtime versions.
	HostVersions() []version.Version
}

type runtime struct { // nolint: maligned
	sync.RWMutex
	startOne cmSync.One

	id                   common.Namespace
	dataDir              string
	registryDescriptor   *registry.Runtime
	activeDescriptor     *registry.Runtime
	activeDescriptorHash hash.Hash
	managed              bool

	consensus    consensus.Backend
	storage      storageAPI.Backend
	localStorage localstorage.LocalStorage

	history history.History

	registryDescriptorCh       chan struct{}
	registryDescriptorNotifier *pubsub.Broker
	activeDescriptorCh         chan struct{}
	activeDescriptorNotifier   *pubsub.Broker

	hostProvisioner runtimeHost.Provisioner
	hostConfig      map[version.Version]*runtimeHost.Config

	logger *logging.Logger
}

func newRuntime(
	runtimeID common.Namespace,
	managed bool,
	dataDir string,
	consensus consensus.Backend,
	provisioner runtimeHost.Provisioner,
	cfg map[version.Version]*runtimeHost.Config,
) (*runtime, error) {
	logger := logging.GetLogger("runtime/registry").With("runtime_id", runtimeID)

	// Ensure runtime state directory exists.
	rtDataDir, err := EnsureRuntimeStateDir(dataDir, runtimeID)
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
		hostProvisioner:            provisioner,
		hostConfig:                 cfg,
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

// HostConfig implements Runtime.
func (r *runtime) HostConfig(version version.Version) *runtimeHost.Config {
	return r.hostConfig[version]
}

// HostProvisioner implements Runtime.
func (r *runtime) HostProvisioner() runtimeHost.Provisioner {
	return r.hostProvisioner
}

// HostVersions implements Runtime.
func (r *runtime) HostVersions() []version.Version {
	var versions []version.Version
	for v := range r.hostConfig {
		versions = append(versions, v)
	}
	return versions
}

// start starts the runtime worker.
func (r *runtime) start() {
	r.startOne.TryStart(r.run)
}

// stop halts the runtime worker.
func (r *runtime) stop() {
	// Stop watching runtime updates.
	r.startOne.TryStop()

	// Close local storage backend.
	r.localStorage.Stop()

	// Close storage backend.
	if r.storage != nil {
		r.storage.Cleanup()
	}

	// Close history keeper.
	if r.history != nil {
		r.history.Close()
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
		case <-epoCh:
			if up := r.updateActiveDescriptor(ctx); up && !activeInitialized {
				close(r.activeDescriptorCh)
				activeInitialized = true
			}
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
			if !activeInitialized && rt.Kind == registry.KindCompute {
				if up := r.updateActiveDescriptor(ctx); up && !activeInitialized {
					close(r.activeDescriptorCh)
					activeInitialized = true
				}
			}
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

	logger *logging.Logger

	dataDir string

	consensus consensus.Backend
	client    runtimeClient.RuntimeClient

	runtimes    map[common.Namespace]*runtime
	runtimesCfg map[common.Namespace]map[version.Version]*runtimeHost.Config

	provisioner    runtimeHost.Provisioner
	historyFactory history.Factory
}

// GetRuntime implements Registry.
func (r *runtimeRegistry) GetRuntime(runtimeID common.Namespace) (Runtime, error) {
	r.RLock()
	defer r.RUnlock()

	rt, ok := r.runtimes[runtimeID]
	if !ok || !rt.managed {
		return nil, fmt.Errorf("runtime/registry: runtime %s not found", runtimeID)
	}
	return rt, nil
}

// Runtimes implements Registry.
func (r *runtimeRegistry) Runtimes() []Runtime {
	r.RLock()
	defer r.RUnlock()

	rts := make([]Runtime, 0, len(r.runtimes))
	for _, rt := range r.runtimes {
		if rt.managed {
			rts = append(rts, rt)
		}
	}
	return rts
}

// NewRuntime implements Registry.
func (r *runtimeRegistry) NewRuntime(ctx context.Context, runtimeID common.Namespace, managed bool) (Runtime, error) {
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

	rt, err := newRuntime(runtimeID, managed, r.dataDir, r.consensus, r.provisioner, r.runtimesCfg[runtimeID])
	if err != nil {
		return nil, err
	}

	if managed {
		// Create runtime history keeper.
		history, err := r.historyFactory(runtimeID, rt.dataDir)
		if err != nil {
			return nil, fmt.Errorf("runtime/registry: cannot create block history for runtime %s: %w", runtimeID, err)
		}
		rt.history = history

		// Start tracking this runtime.
		if err = r.consensus.RootHash().TrackRuntime(ctx, history); err != nil {
			return nil, fmt.Errorf("runtime/registry: cannot track runtime %s: %w", runtimeID, err)
		}
	}

	r.runtimes[runtimeID] = rt

	rt.start()

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

// Cleanup implements Registry.
func (r *runtimeRegistry) Cleanup() {
	r.Lock()
	defer r.Unlock()

	for _, rt := range r.runtimes {
		rt.stop()
	}
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

// New creates a new runtime registry.
func New(
	ctx context.Context,
	dataDir string,
	commonStore *persistent.CommonStore,
	identity *identity.Identity,
	consensus consensus.Backend,
	ias []ias.Endpoint,
) (Registry, error) {
	// Create history keeper factory.
	historyFactory, err := createHistoryFactory()
	if err != nil {
		return nil, err
	}

	// Configure host environment information.
	hostInfo, err := createHostInfo(consensus)
	if err != nil {
		return nil, err
	}

	// Create the PCS client and quote service.
	qs, err := createCachingQuoteService(commonStore)
	if err != nil {
		return nil, err
	}

	// Create runtime provisioner.
	provisioner, err := createProvisioner(commonStore, identity, consensus, hostInfo, ias, qs)
	if err != nil {
		return nil, err
	}

	runtimesCfg, err := newRuntimeConfig(dataDir)
	if err != nil {
		return nil, err
	}

	r := &runtimeRegistry{
		logger:         logging.GetLogger("runtime/registry"),
		dataDir:        dataDir,
		consensus:      consensus,
		runtimes:       make(map[common.Namespace]*runtime),
		runtimesCfg:    runtimesCfg,
		provisioner:    provisioner,
		historyFactory: historyFactory,
	}

	if config.GlobalConfig.Mode == config.ModeKeyManager {
		return r, nil
	}

	for runtimeID := range runtimesCfg {
		if _, err := r.NewRuntime(ctx, runtimeID, true); err != nil {
			r.logger.Error("failed to add runtime",
				"err", err,
				"id", runtimeID,
			)
			return nil, fmt.Errorf("failed to add runtime %s: %w", runtimeID, err)
		}
	}

	return r, nil
}
