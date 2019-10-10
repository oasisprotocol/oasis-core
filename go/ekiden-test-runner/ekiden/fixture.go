package ekiden

import (
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

// NetworkFixture describes configuration for the test Ekiden network and
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
	Clients        []ClientFixture        `json:"clients,omitempty"`
	ByzantineNodes []ByzantineFixture     `json:"byzantine_nodes,omitempty"`
}

// Create instantiates the network described by the fixture.
func (f *NetworkFixture) Create(env *env.Env) (*Network, error) {
	// Use default MRSIGNER if not provided.
	if f.TEE.Hardware == node.TEEHardwareIntelSGX && f.TEE.MrSigner == nil {
		f.TEE.MrSigner = &ias.FortanixTestMrSigner
	}

	// Create the top level ekiden network.
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
	MrSigner *sgx.MrSigner    `json:"mrsigner"`
}

// ValidatorFixture is a validator fixture.
type ValidatorFixture struct {
	Entity int `json:"entity"`
}

// Create instantiates the validator described by the fixture.
func (f *ValidatorFixture) Create(net *Network) (*Validator, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewValidator(&ValidatorCfg{
		Entity: entity,
	})
}

// RuntimeFixture is a runtime fixture.
type RuntimeFixture struct {
	ID         signature.PublicKey  `json:"id"`
	Kind       registry.RuntimeKind `json:"kind"`
	Entity     int                  `json:"entity"`
	Keymanager int                  `json:"keymanager"`

	Binary       string `json:"binary"`
	GenesisState string `json:"genesis_state"`

	ReplicaGroupSize       int `json:"replica_group_size"`
	ReplicaGroupBackupSize int `json:"replica_group_backup_size"`
	StorageGroupSize       int `json:"storage_group_size"`
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
		ID:                     f.ID,
		Kind:                   f.Kind,
		Entity:                 entity,
		Keymanager:             km,
		TEEHardware:            netFixture.TEE.Hardware,
		MrSigner:               netFixture.TEE.MrSigner,
		ReplicaGroupSize:       f.ReplicaGroupSize,
		ReplicaGroupBackupSize: f.ReplicaGroupBackupSize,
		StorageGroupSize:       f.StorageGroupSize,
		Binary:                 f.Binary,
		GenesisState:           f.GenesisState,
	})
}

// KeymanagerFixture is a key manager fixture.
type KeymanagerFixture struct {
	Runtime int `json:"runtime"`
	Entity  int `json:"entity"`

	Restartable bool `json:"restartable"`
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
		Runtime:     runtime,
		Entity:      entity,
		Restartable: f.Restartable,
	})
}

// StorageWorkerFixture is a storage worker fixture.
type StorageWorkerFixture struct {
	Backend string `json:"backend"`
	Entity  int    `json:"entity"`

	IgnoreApplies bool `json:"ignore_applies,omitempty"`
}

// Create instantiates the storage worker described by the fixture.
func (f *StorageWorkerFixture) Create(net *Network) (*Storage, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewStorage(&StorageCfg{
		Backend:       f.Backend,
		Entity:        entity,
		IgnoreApplies: f.IgnoreApplies,
	})
}

// ComputeWorkerFixture is a compute worker fixture.
type ComputeWorkerFixture struct {
	Entity int `json:"entity"`

	RuntimeBackend string `json:"runtime_backend"`
}

// Create instantiates the compute worker described by the fixture.
func (f *ComputeWorkerFixture) Create(net *Network) (*Compute, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewCompute(&ComputeCfg{
		Entity:         entity,
		RuntimeBackend: f.RuntimeBackend,
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
}

// Create instantiates the byzantine node described by the fixture.
func (f *ByzantineFixture) Create(net *Network) (*Byzantine, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewByzantine(&ByzantineCfg{
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
