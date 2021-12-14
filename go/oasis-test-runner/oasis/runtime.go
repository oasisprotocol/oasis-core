package oasis

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

const (
	rtDescriptorFile = "runtime_genesis.json"
)

// Runtime is an Oasis runtime.
type Runtime struct { // nolint: maligned
	dir *env.Dir

	id   common.Namespace
	kind registry.RuntimeKind

	binaries    map[node.TEEHardware][]string
	teeHardware node.TEEHardware
	mrEnclaves  []*sgx.MrEnclave
	mrSigner    *sgx.MrSigner

	pruner RuntimePrunerCfg

	excludeFromGenesis bool
	descriptor         registry.Runtime
	genesisState       string
}

// RuntimeCfg is the Oasis runtime provisioning configuration.
type RuntimeCfg struct { // nolint: maligned
	ID          common.Namespace
	Kind        registry.RuntimeKind
	Entity      *Entity
	Keymanager  *Runtime
	TEEHardware node.TEEHardware
	MrSigner    *sgx.MrSigner
	Version     version.Version

	Binaries         map[node.TEEHardware][]string
	GenesisState     storage.WriteLog
	GenesisStatePath string
	GenesisRound     uint64

	Executor     registry.ExecutorParameters
	TxnScheduler registry.TxnSchedulerParameters
	Storage      registry.StorageParameters

	AdmissionPolicy registry.RuntimeAdmissionPolicy
	Constraints     map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints
	Staking         registry.RuntimeStakingParameters

	GovernanceModel registry.RuntimeGovernanceModel

	Pruner RuntimePrunerCfg

	ExcludeFromGenesis bool
}

// RuntimePrunerCfg is the pruner configuration for an Oasis runtime.
type RuntimePrunerCfg struct {
	Strategy string        `json:"strategy"`
	Interval time.Duration `json:"interval"`

	NumKept uint64 `json:"num_kept"`
}

// ID returns the runtime ID.
func (rt *Runtime) ID() common.Namespace {
	return rt.id
}

// Kind returns the runtime kind.
func (rt *Runtime) Kind() registry.RuntimeKind {
	return rt.kind
}

// GetEnclaveIdentity returns the runtime's enclave ID.
func (rt *Runtime) GetEnclaveIdentity() *sgx.EnclaveIdentity {
	if rt.mrEnclaves != nil && rt.mrSigner != nil {
		return &sgx.EnclaveIdentity{
			MrEnclave: *rt.mrEnclaves[0],
			MrSigner:  *rt.mrSigner,
		}
	}
	return nil
}

// RefreshEnclaveIdentity refreshes the enclave identity for the runtime.
func (rt *Runtime) RefreshEnclaveIdentity() error {
	switch rt.teeHardware {
	case node.TEEHardwareIntelSGX:
		var mrEnclaves []*sgx.MrEnclave
		enclaveIdentities := []sgx.EnclaveIdentity{}
		for _, binary := range rt.binaries[node.TEEHardwareIntelSGX] {
			var (
				mrEnclave *sgx.MrEnclave
				err       error
			)
			if mrEnclave, err = deriveMrEnclave(binary); err != nil {
				return err
			}
			enclaveIdentities = append(enclaveIdentities, sgx.EnclaveIdentity{MrEnclave: *mrEnclave, MrSigner: *rt.mrSigner})
			mrEnclaves = append(mrEnclaves, mrEnclave)
		}
		rt.descriptor.Version.TEE = cbor.Marshal(node.SGXConstraints{
			Enclaves: enclaveIdentities,
		})
		rt.mrEnclaves = mrEnclaves
		return nil
	default:
		return nil
	}
}

func (rt *Runtime) toGenesisArgs() []string {
	if rt.excludeFromGenesis {
		return []string{}
	}

	return []string{
		"--runtime", filepath.Join(rt.dir.String(), rtDescriptorFile),
	}
}

// ToRuntimeDescriptor returns a registry runtime descriptor for this runtime.
func (rt *Runtime) ToRuntimeDescriptor() registry.Runtime {
	return rt.descriptor
}

// NewRuntime provisions a new runtime and adds it to the network.
func (net *Network) NewRuntime(cfg *RuntimeCfg) (*Runtime, error) {
	descriptor := registry.Runtime{
		Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:              cfg.ID,
		EntityID:        cfg.Entity.entity.ID,
		Kind:            cfg.Kind,
		TEEHardware:     cfg.TEEHardware,
		Version:         registry.VersionInfo{Version: cfg.Version},
		Executor:        cfg.Executor,
		TxnScheduler:    cfg.TxnScheduler,
		Storage:         cfg.Storage,
		AdmissionPolicy: cfg.AdmissionPolicy,
		Constraints:     cfg.Constraints,
		Staking:         cfg.Staking,
		GovernanceModel: cfg.GovernanceModel,
	}
	descriptor.Genesis.StateRoot.Empty()

	rtDir, err := net.baseDir.NewSubDir("runtime-" + cfg.ID.String())
	if err != nil {
		net.logger.Error("failed to create runtime subdir",
			"err", err,
		)
		return nil, fmt.Errorf("oasis/runtime: failed to create runtime subdir: %w", err)
	}

	genesisStatePath := cfg.GenesisStatePath
	if cfg.GenesisState != nil && genesisStatePath != "" {
		return nil, fmt.Errorf("oasis/runtime: inline genesis state and file genesis state set")
	}

	log := cfg.GenesisState

	if genesisStatePath != "" {
		var b []byte
		b, err = ioutil.ReadFile(genesisStatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load runtime genesis storage state: %w", err)
		}

		if err = json.Unmarshal(b, &log); err != nil {
			return nil, fmt.Errorf("failed to parse runtime genesis storage state: %w", err)
		}
	}
	if log != nil {
		descriptor.Genesis.Round = cfg.GenesisRound
		// Use in-memory MKVS tree to calculate the new root.
		tree := mkvs.New(nil, nil, storage.RootTypeState)
		ctx := context.Background()
		for _, logEntry := range log {
			err = tree.Insert(ctx, logEntry.Key, logEntry.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to apply runtime genesis storage state: %w", err)
			}
		}

		var newRoot hash.Hash
		_, newRoot, err = tree.Commit(ctx, descriptor.ID, descriptor.Genesis.Round)
		if err != nil {
			return nil, fmt.Errorf("failed to apply runtime genesis storage state: %w", err)
		}

		descriptor.Genesis.StateRoot = newRoot
		descriptor.Genesis.State = log
	}

	if cfg.Keymanager != nil {
		descriptor.KeyManager = new(common.Namespace)
		*descriptor.KeyManager = cfg.Keymanager.id
	}

	rt := &Runtime{
		dir:                rtDir,
		id:                 cfg.ID,
		kind:               cfg.Kind,
		binaries:           cfg.Binaries,
		teeHardware:        cfg.TEEHardware,
		mrSigner:           cfg.MrSigner,
		pruner:             cfg.Pruner,
		excludeFromGenesis: cfg.ExcludeFromGenesis,
		descriptor:         descriptor,
		genesisState:       genesisStatePath,
	}

	if err := rt.RefreshEnclaveIdentity(); err != nil {
		return nil, err
	}

	// Save runtime descriptor into file.
	rtDescStr, _ := json.Marshal(rt.descriptor)
	path := filepath.Join(rtDir.String(), rtDescriptorFile)
	if err := ioutil.WriteFile(path, rtDescStr, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write runtime descriptor to file: %w", err)
	}

	net.runtimes = append(net.runtimes, rt)

	return rt, nil
}

func deriveMrEnclave(f string) (*sgx.MrEnclave, error) {
	r, err := os.Open(f)
	if err != nil {
		return nil, fmt.Errorf("oasis: failed to open enclave binary: %w", err)
	}
	defer r.Close()

	var m sgx.MrEnclave
	if err = m.FromSgxs(r); err != nil {
		return nil, err
	}

	return &m, nil
}
