package oasis

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/log"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

// NetworkFixture describes configuration for the test Oasis network and
// all the spawned nodes.
type NetworkFixture struct {
	TEE            TEEFixture             `json:"tee,omitempty"`
	Network        NetworkCfg             `json:"network,omitempty"`
	Entities       []EntityCfg            `json:"entities,omitempty"`
	Runtimes       []RuntimeFixture       `json:"runtimes,omitempty"`
	Validators     []ValidatorFixture     `json:"validators,omitempty"`
	Keymanagers    []KeymanagerFixture    `json:"keymanagers,omitempty"`
	StorageWorkers []StorageWorkerFixture `json:"storage_workers,omitempty"`
	ComputeWorkers []ComputeWorkerFixture `json:"compute_workers,omitempty"`
	Sentries       []SentryFixture        `json:"sentries,omitempty"`
	Clients        []ClientFixture        `json:"clients,omitempty"`
	ByzantineNodes []ByzantineFixture     `json:"byzantine_nodes,omitempty"`
}

// Create instantiates the network described by the fixture.
func (f *NetworkFixture) Create(env *env.Env) (*Network, error) {
	// Use default MRSIGNER if not provided.
	if f.TEE.Hardware == node.TEEHardwareIntelSGX && f.TEE.MrSigner == nil {
		f.TEE.MrSigner = &ias.FortanixTestMrSigner
	}

	// Create the top level Oasis network.
	var net *Network
	var err error
	if net, err = New(env, &f.Network); err != nil {
		return nil, err
	}

	// Provision entities.
	for _, entCfg := range f.Entities {
		if _, err = net.NewEntity(&entCfg); err != nil {
			return nil, fmt.Errorf("failed to provision entity: %w", err)
		}
	}

	// Provision runtimes.
	for _, fx := range f.Runtimes {
		if _, err = fx.Create(f, net); err != nil {
			return nil, err
		}
	}

	// Provision the sentry nodes.
	for _, fx := range f.Sentries {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision validators.
	for _, fx := range f.Validators {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision key managers.
	for _, fx := range f.Keymanagers {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision the storage workers.
	for _, fx := range f.StorageWorkers {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision the compute workers.
	for _, fx := range f.ComputeWorkers {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision the client nodes.
	for _, fx := range f.Clients {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision the Byzantine nodes.
	for _, fx := range f.ByzantineNodes {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	return net, nil
}

// TEEFixture is a TEE configuration fixture.
type TEEFixture struct {
	Hardware node.TEEHardware `json:"hardware"`
	MrSigner *sgx.MrSigner    `json:"mr_signer"`
}

// ValidatorFixture is a validator fixture.
type ValidatorFixture struct {
	Restartable bool `json:"restartable"`

	Entity int `json:"entity"`

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	MinGasPrice uint64 `json:"min_gas_price"`

	Sentries []int `json:"sentries,omitempty"`
}

// Create instantiates the validator described by the fixture.
func (f *ValidatorFixture) Create(net *Network) (*Validator, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}
	sentries, err := resolveSentries(net, f.Sentries)
	if err != nil {
		return nil, err
	}

	return net.NewValidator(&ValidatorCfg{
		NodeCfg: NodeCfg{
			Restartable:                f.Restartable,
			LogWatcherHandlerFactories: f.LogWatcherHandlerFactories,
		},
		Entity:      entity,
		MinGasPrice: f.MinGasPrice,
		Sentries:    sentries,
	})
}

// RuntimeFixture is a runtime fixture.
type RuntimeFixture struct {
	ID         common.Namespace     `json:"id"`
	Kind       registry.RuntimeKind `json:"kind"`
	Entity     int                  `json:"entity"`
	Keymanager int                  `json:"keymanager"`

	Binary       string `json:"binary"`
	GenesisState string `json:"genesis_state"`
	GenesisRound uint64 `json:"genesis_round"`

	Compute      registry.ComputeParameters      `json:"compute"`
	Merge        registry.MergeParameters        `json:"merge"`
	TxnScheduler registry.TxnSchedulerParameters `json:"txn_scheduler"`
	Storage      registry.StorageParameters      `json:"storage"`

	Pruner RuntimePrunerCfg `json:"pruner,omitempty"`
}

// Create instantiates the runtime described by the fixture.
func (f *RuntimeFixture) Create(netFixture *NetworkFixture, net *Network) (*Runtime, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	var km *Runtime
	if f.Keymanager != -1 {
		switch f.Kind {
		case registry.KindCompute:
			if km, err = resolveRuntimeOfKind(net, f.Keymanager, registry.KindKeyManager); err != nil {
				return nil, err
			}
		case registry.KindKeyManager:
			return nil, fmt.Errorf("key manager runtime cannot have a key manager")
		}
	}

	return net.NewRuntime(&RuntimeCfg{
		ID:           f.ID,
		Kind:         f.Kind,
		Entity:       entity,
		Keymanager:   km,
		TEEHardware:  netFixture.TEE.Hardware,
		MrSigner:     netFixture.TEE.MrSigner,
		Compute:      f.Compute,
		Merge:        f.Merge,
		TxnScheduler: f.TxnScheduler,
		Storage:      f.Storage,
		Binary:       f.Binary,
		GenesisState: f.GenesisState,
		GenesisRound: f.GenesisRound,
		Pruner:       f.Pruner,
	})
}

// KeymanagerFixture is a key manager fixture.
type KeymanagerFixture struct {
	Runtime int `json:"runtime"`
	Entity  int `json:"entity"`

	Restartable bool `json:"restartable"`

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`
}

// Create instantiates the key manager described by the fixture.
func (f *KeymanagerFixture) Create(net *Network) (*Keymanager, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}
	runtime, err := resolveRuntimeOfKind(net, f.Runtime, registry.KindKeyManager)
	if err != nil {
		return nil, err
	}

	return net.NewKeymanager(&KeymanagerCfg{
		NodeCfg: NodeCfg{
			Restartable:                f.Restartable,
			LogWatcherHandlerFactories: f.LogWatcherHandlerFactories,
		},
		Runtime: runtime,
		Entity:  entity,
	})
}

// StorageWorkerFixture is a storage worker fixture.
type StorageWorkerFixture struct {
	Backend string `json:"backend"`
	Entity  int    `json:"entity"`

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	IgnoreApplies bool `json:"ignore_applies,omitempty"`
}

// Create instantiates the storage worker described by the fixture.
func (f *StorageWorkerFixture) Create(net *Network) (*Storage, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewStorage(&StorageCfg{
		NodeCfg: NodeCfg{
			LogWatcherHandlerFactories: f.LogWatcherHandlerFactories,
		},
		Backend:       f.Backend,
		Entity:        entity,
		IgnoreApplies: f.IgnoreApplies,
	})
}

// ComputeWorkerFixture is a compute worker fixture.
type ComputeWorkerFixture struct {
	Entity int `json:"entity"`

	RuntimeBackend string `json:"runtime_backend"`

	Restartable bool `json:"restartable"`

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`
}

// Create instantiates the compute worker described by the fixture.
func (f *ComputeWorkerFixture) Create(net *Network) (*Compute, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewCompute(&ComputeCfg{
		NodeCfg: NodeCfg{
			Restartable:                f.Restartable,
			LogWatcherHandlerFactories: f.LogWatcherHandlerFactories,
		},
		Entity:         entity,
		RuntimeBackend: f.RuntimeBackend,
	})
}

// SentryFixture is a sentry node fixture.
type SentryFixture struct {
	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	Validators []int `json:"validators"`
}

// Create instantiates the client node described by the fixture.
func (f *SentryFixture) Create(net *Network) (*Sentry, error) {
	return net.NewSentry(&SentryCfg{
		NodeCfg: NodeCfg{
			LogWatcherHandlerFactories: f.LogWatcherHandlerFactories,
		},
		ValidatorIndices: f.Validators,
	})
}

// ClientFixture is a client node fixture.
type ClientFixture struct {
}

// Create instantiates the client node described by the fixture.
func (f *ClientFixture) Create(net *Network) (*Client, error) {
	return net.NewClient()
}

// ByzantineFixture is a byzantine node fixture.
type ByzantineFixture struct {
	Script       string `json:"script"`
	IdentitySeed string `json:"identity_seed"`
	Entity       int    `json:"entity"`

	EnableDefaultLogWatcherHandlerFactories bool                        `json:"enable_default_log_fac"`
	LogWatcherHandlerFactories              []log.WatcherHandlerFactory `json:"-"`
}

// Create instantiates the byzantine node described by the fixture.
func (f *ByzantineFixture) Create(net *Network) (*Byzantine, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewByzantine(&ByzantineCfg{
		NodeCfg: NodeCfg{
			DisableDefaultLogWatcherHandlerFactories: !f.EnableDefaultLogWatcherHandlerFactories,
			LogWatcherHandlerFactories:               f.LogWatcherHandlerFactories,
		},
		Script:       f.Script,
		IdentitySeed: f.IdentitySeed,
		Entity:       entity,
	})
}

func resolveEntity(net *Network, index int) (*Entity, error) {
	entities := net.Entities()
	if index < 0 || index >= len(entities) {
		return nil, fmt.Errorf("invalid entity index: %d", index)
	}
	return entities[index], nil
}

func resolveValidators(net *Network, indices []int) ([]*Validator, error) {
	allValidators := net.Validators()
	var validators []*Validator
	for _, index := range indices {
		if index < 0 || index >= len(allValidators) {
			return nil, fmt.Errorf("invalid validator index: %d", index)
		}
		validators = append(validators, allValidators[index])
	}
	return validators, nil
}

func resolveRuntime(net *Network, index int) (*Runtime, error) {
	runtimes := net.Runtimes()
	if index < 0 || index >= len(runtimes) {
		return nil, fmt.Errorf("invalid runtime index: %d", index)
	}
	return runtimes[index], nil
}

func resolveRuntimeOfKind(net *Network, index int, kind registry.RuntimeKind) (*Runtime, error) {
	runtime, err := resolveRuntime(net, index)
	if err != nil {
		return nil, err
	}
	if runtime.kind != kind {
		return nil, fmt.Errorf("runtime %d has an incorrect kind (expected: %s got: %s)",
			index,
			kind,
			runtime.kind,
		)
	}
	return runtime, nil
}

func resolveSentries(net *Network, indices []int) ([]*Sentry, error) {
	allSentries := net.Sentries()
	var sentries []*Sentry
	for _, index := range indices {
		if index < 0 || index >= len(allSentries) {
			return nil, fmt.Errorf("invalid sentry index: %d", index)
		}
		sentries = append(sentries, allSentries[index])
	}
	return sentries, nil
}
