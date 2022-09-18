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
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
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
	// Mode returns the configured behavior of runtime workers on this node.
	Mode() RuntimeMode

	// GetRuntime returns the per-runtime interface if the runtime is supported.
	GetRuntime(runtimeID common.Namespace) (Runtime, error)

	// Runtimes returns a list of all supported runtimes.
	Runtimes() []Runtime

	// NewUnmanagedRuntime creates a new runtime that is not managed by this
	// registry.
	NewUnmanagedRuntime(ctx context.Context, runtimeID common.Namespace) (Runtime, error)

	// AddRoles adds available node roles to the runtime. Specify nil as the runtimeID
	// to set the role for all runtimes.
	AddRoles(roles node.RolesMask, runtimeID *common.Namespace) error

	// Cleanup performs post-termination cleanup.
	Cleanup()

	// FinishInitialization finalizes setup for all runtimes.
	FinishInitialization(ctx context.Context) error
}

// Runtime is the running node's supported runtime interface.
type Runtime interface {
	// ID is the runtime identifier.
	ID() common.Namespace

	// Mode returns the configured behavior of runtime workers on this node.
	Mode() RuntimeMode

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

	// AddRoles adds available node roles to the runtime.
	AddRoles(roles node.RolesMask)

	// HasRoles checks if the node has all of the roles specified for this runtime.
	HasRoles(roles node.RolesMask) bool

	// History returns the history for this runtime.
	History() history.History

	// Storage returns the per-runtime storage backend.
	Storage() storageAPI.Backend

	// LocalStorage returns the per-runtime local storage.
	LocalStorage() localstorage.LocalStorage

	// HasHost checks whether this runtime can be hosted by the current node.
	HasHost() bool

	// Host returns the runtime host configuration and provisioner if configured.
	Host(ctx context.Context) (map[version.Version]*runtimeHost.Config, runtimeHost.Provisioner, error)

	// HostVersions returns a list of supported runtime versions.
	HostVersions() []version.Version
}

type runtime struct { // nolint: maligned
	sync.RWMutex

	id                   common.Namespace
	dataDir              string
	mode                 RuntimeMode
	registryDescriptor   *registry.Runtime
	activeDescriptor     *registry.Runtime
	activeDescriptorHash hash.Hash
	roles                node.RolesMask
	managed              bool

	consensus    consensus.Backend
	storage      storageAPI.Backend
	localStorage localstorage.LocalStorage

	history history.History

	cancelCtx                  context.CancelFunc
	registryDescriptorCh       chan struct{}
	registryDescriptorNotifier *pubsub.Broker
	activeDescriptorCh         chan struct{}
	activeDescriptorNotifier   *pubsub.Broker

	hostProvisioners map[node.TEEHardware]runtimeHost.Provisioner
	hostConfig       map[version.Version]*runtimeHost.Config

	logger *logging.Logger
}

func (r *runtime) ID() common.Namespace {
	return r.id
}

func (r *runtime) Mode() RuntimeMode {
	return r.mode
}

func (r *runtime) DataDir() string {
	return r.dataDir
}

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

func (r *runtime) WatchActiveDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error) {
	sub := r.activeDescriptorNotifier.Subscribe()
	ch := make(chan *registry.Runtime)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *runtime) WatchRegistryDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error) {
	sub := r.registryDescriptorNotifier.Subscribe()
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

func (r *runtime) AddRoles(roles node.RolesMask) {
	r.Lock()
	defer r.Unlock()

	r.roles |= roles
}

func (r *runtime) HasRoles(roles node.RolesMask) bool {
	r.Lock()
	defer r.Unlock()

	return r.roles&roles == roles
}

func (r *runtime) History() history.History {
	return r.history
}

func (r *runtime) Storage() storageAPI.Backend {
	r.RLock()
	defer r.RUnlock()

	if r.storage == nil && r.managed {
		panic("runtime storage accessed before initialization")
	}
	return r.storage
}

func (r *runtime) LocalStorage() localstorage.LocalStorage {
	return r.localStorage
}

func (r *runtime) HasHost() bool {
	return r.hostProvisioners != nil && r.hostConfig != nil
}

func (r *runtime) Host(ctx context.Context) (map[version.Version]*runtimeHost.Config, runtimeHost.Provisioner, error) {
	if r.hostProvisioners == nil || r.hostConfig == nil {
		return nil, nil, ErrRuntimeHostNotConfigured
	}

	rt, err := r.RegistryDescriptor(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get runtime registry descriptor: %w", err)
	}

	provisioner, ok := r.hostProvisioners[rt.TEEHardware]
	if !ok {
		return nil, nil, fmt.Errorf("no provisioner suitable for TEE hardware '%s'", rt.TEEHardware)
	}

	return r.hostConfig, provisioner, nil
}

func (r *runtime) HostVersions() []version.Version {
	var versions []version.Version
	for v := range r.hostConfig {
		versions = append(versions, v)
	}
	return versions
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
	// Close history keeper.
	if r.history != nil {
		r.history.Close()
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
	// This is only called from the watchUpdates thread and activeDescriptorHash
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

func (r *runtime) watchUpdates(ctx context.Context) {
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

func (r *runtime) finishInitialization(ctx context.Context) error {
	r.Lock()
	defer r.Unlock()

	if r.storage == nil {
		return fmt.Errorf("runtime/registry: nobody provided a storage backend for runtime %s", r.id)
	}

	return nil
}

type runtimeRegistry struct {
	sync.RWMutex

	logger *logging.Logger

	dataDir string
	cfg     *RuntimeConfig

	consensus consensus.Backend

	runtimes map[common.Namespace]*runtime
}

func (r *runtimeRegistry) Mode() RuntimeMode {
	return r.cfg.Mode
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
	return newRuntime(ctx, r.dataDir, runtimeID, r.cfg, r.consensus, r.logger)
}

func (r *runtimeRegistry) AddRoles(roles node.RolesMask, runtimeID *common.Namespace) error {
	r.RLock()
	defer r.RUnlock()

	if runtimeID != nil {
		rt, ok := r.runtimes[*runtimeID]
		if !ok {
			return fmt.Errorf("runtime/registry: runtime %s is not supported", *runtimeID)
		}
		rt.AddRoles(roles)
		return nil
	}

	for _, rt := range r.runtimes {
		rt.AddRoles(roles)
	}
	return nil
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
		if err := rt.finishInitialization(ctx); err != nil {
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

	rt, err := newRuntime(ctx, r.dataDir, id, r.cfg, r.consensus, r.logger)
	if err != nil {
		return err
	}
	defer func() {
		if rerr != nil {
			rt.stop()
		}
	}()
	rt.managed = true

	// Create runtime history keeper.
	// NOTE: Archive node won't commit any new blocks, so disable waiting for storage sync commits.
	haveLocalStorageWorker := r.cfg.Mode.HasLocalStorage() && r.consensus.Mode() != consensus.ModeArchive
	history, err := history.New(rt.dataDir, id, &r.cfg.History, haveLocalStorageWorker)
	if err != nil {
		return fmt.Errorf("runtime/registry: cannot create block history for runtime %s: %w", id, err)
	}

	// Create runtime-specific storage backend.
	var ns common.Namespace
	copy(ns[:], id[:])

	// Start tracking this runtime.
	if err = r.consensus.RootHash().TrackRuntime(ctx, history); err != nil {
		return fmt.Errorf("runtime/registry: cannot track runtime %s: %w", id, err)
	}

	rt.history = history
	r.runtimes[id] = rt

	return nil
}

func newRuntime(
	ctx context.Context,
	dataDir string,
	id common.Namespace,
	cfg *RuntimeConfig,
	consensus consensus.Backend,
	logger *logging.Logger,
) (*runtime, error) {
	// Ensure runtime state directory exists.
	rtDataDir, err := EnsureRuntimeStateDir(dataDir, id)
	if err != nil {
		return nil, err
	}

	// Create runtime-specific local storage backend.
	localStorage, err := localstorage.New(rtDataDir, LocalStorageFile, id)
	if err != nil {
		return nil, fmt.Errorf("runtime/registry: cannot create local storage for runtime %s: %w", id, err)
	}

	watchCtx, cancel := context.WithCancel(ctx)

	rt := &runtime{
		id:                         id,
		dataDir:                    rtDataDir,
		mode:                       cfg.Mode,
		consensus:                  consensus,
		localStorage:               localStorage,
		cancelCtx:                  cancel,
		registryDescriptorCh:       make(chan struct{}),
		registryDescriptorNotifier: pubsub.NewBroker(true),
		activeDescriptorCh:         make(chan struct{}),
		activeDescriptorNotifier:   pubsub.NewBroker(true),
		logger:                     logger.With("runtime_id", id),
	}
	go rt.watchUpdates(watchCtx)

	// Configure runtime host if needed.
	if cfg.Host != nil {
		rt.hostProvisioners = cfg.Host.Provisioners
		rt.hostConfig = cfg.Host.Runtimes[id]
	}

	return rt, nil
}

// New creates a new runtime registry.
func New(ctx context.Context, dataDir string, consensus consensus.Backend, ias ias.Endpoint) (Registry, error) {
	cfg, err := newConfig(dataDir, consensus, ias)
	if err != nil {
		return nil, err
	}

	r := &runtimeRegistry{
		logger:    logging.GetLogger("runtime/registry"),
		dataDir:   dataDir,
		cfg:       cfg,
		consensus: consensus,
		runtimes:  make(map[common.Namespace]*runtime),
	}

	switch cfg.Mode {
	case RuntimeModeNone:
		r.logger.Info("runtime support is disabled")
	default:
		r.logger.Info("runtime support is enabled",
			"mode", cfg.Mode,
		)
	}

	for _, id := range cfg.Runtimes() {
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

	return r, nil
}
