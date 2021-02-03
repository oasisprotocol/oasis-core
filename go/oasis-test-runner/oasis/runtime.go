package oasis

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

const (
	rtDescriptorFile = "runtime_genesis.json"
	rtStateFile      = "runtime_genesis_state.json"
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

	Binaries         map[node.TEEHardware][]string
	GenesisState     storage.WriteLog
	GenesisStatePath string
	GenesisRound     uint64

	Executor     registry.ExecutorParameters
	TxnScheduler registry.TxnSchedulerParameters
	Storage      registry.StorageParameters

	AdmissionPolicy registry.RuntimeAdmissionPolicy
	Staking         registry.RuntimeStakingParameters

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

// GetGenesisStatePath returns the path to the runtime genesis state file (if any).
func (rt *Runtime) GetGenesisStatePath() string {
	return rt.genesisState
}

// NewRuntime provisions a new runtime and adds it to the network.
func (net *Network) NewRuntime(cfg *RuntimeCfg) (*Runtime, error) {
	descriptor := registry.Runtime{
		Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:              cfg.ID,
		EntityID:        cfg.Entity.entity.ID,
		Kind:            cfg.Kind,
		TEEHardware:     cfg.TEEHardware,
		Executor:        cfg.Executor,
		TxnScheduler:    cfg.TxnScheduler,
		Storage:         cfg.Storage,
		AdmissionPolicy: cfg.AdmissionPolicy,
		Staking:         cfg.Staking,
		GovernanceModel: registry.GovernanceEntity,
	}

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
	if cfg.GenesisState != nil || genesisStatePath != "" {
		descriptor.Genesis.Round = cfg.GenesisRound
		if cfg.GenesisState != nil {
			genesisStatePath = filepath.Join(rtDir.String(), rtStateFile)
			var b []byte
			if b, err = json.Marshal(cfg.GenesisState); err != nil {
				return nil, fmt.Errorf("oasis/runtime: failed to serialize runtime genesis state: %w", err)
			}
			if err = ioutil.WriteFile(genesisStatePath, b, 0o600); err != nil {
				return nil, fmt.Errorf("oasis/runtime: failed to write runtime genesis file: %w", err)
			}
		}
	}
	var mrEnclaves []*sgx.MrEnclave
	if cfg.TEEHardware == node.TEEHardwareIntelSGX {
		enclaveIdentities := []sgx.EnclaveIdentity{}
		for _, binary := range cfg.Binaries[node.TEEHardwareIntelSGX] {
			var mrEnclave *sgx.MrEnclave
			if mrEnclave, err = deriveMrEnclave(binary); err != nil {
				return nil, err
			}
			enclaveIdentities = append(enclaveIdentities, sgx.EnclaveIdentity{MrEnclave: *mrEnclave, MrSigner: *cfg.MrSigner})
			mrEnclaves = append(mrEnclaves, mrEnclave)
		}
		descriptor.Version.TEE = cbor.Marshal(registry.VersionInfoIntelSGX{
			Enclaves: enclaveIdentities,
		})
	}
	if cfg.Keymanager != nil {
		descriptor.KeyManager = new(common.Namespace)
		*descriptor.KeyManager = cfg.Keymanager.id
	}

	// Provision a runtime descriptor suitable for the genesis block.
	cli := cli.New(net.env, net, net.logger)
	extraArgs := append([]string{},
		"--"+cmdCommon.CfgDataDir, rtDir.String(),
	)
	extraArgs = append(extraArgs, cfg.Entity.toGenesisArgs()...)
	if err = cli.Registry.InitGenesis(descriptor, genesisStatePath, extraArgs...); err != nil {
		net.logger.Error("failed to provision runtime",
			"err", err,
		)
		return nil, fmt.Errorf("oasis/runtime: failed to provision runtime: %w", err)
	}

	rt := &Runtime{
		dir:                rtDir,
		id:                 cfg.ID,
		kind:               cfg.Kind,
		binaries:           cfg.Binaries,
		teeHardware:        cfg.TEEHardware,
		mrEnclaves:         mrEnclaves,
		mrSigner:           cfg.MrSigner,
		pruner:             cfg.Pruner,
		excludeFromGenesis: cfg.ExcludeFromGenesis,
		descriptor:         descriptor,
		genesisState:       genesisStatePath,
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
