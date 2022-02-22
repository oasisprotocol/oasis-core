package oasis

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const rtDescriptorFile = "runtime_genesis.json"

type runtimeCfgSave struct {
	id       common.Namespace
	version  version.Version
	binaries map[node.TEEHardware]string
}

// Runtime is an Oasis runtime.
type Runtime struct { // nolint: maligned
	dir *env.Dir

	bundle *bundle.Bundle
	kind   registry.RuntimeKind

	// This refers to things that ostensibly are canonically held
	// in the runtime bundle manifest.  Accessing this field outside
	// of this file is discouraged (if not entirely forbidden).
	cfgSave runtimeCfgSave

	teeHardware node.TEEHardware
	mrEnclave   *sgx.MrEnclave
	mrSigner    *sgx.MrSigner

	pruner RuntimePrunerCfg

	excludeFromGenesis bool
	descriptor         registry.Runtime
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

	Binaries     map[node.TEEHardware]string
	GenesisRound uint64

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
	return rt.cfgSave.id
}

// Kind returns the runtime kind.
func (rt *Runtime) Kind() registry.RuntimeKind {
	return rt.kind
}

// GetEnclaveIdentity returns the runtime's enclave ID.
func (rt *Runtime) GetEnclaveIdentity() *sgx.EnclaveIdentity {
	if rt.mrEnclave != nil && rt.mrSigner != nil {
		return &sgx.EnclaveIdentity{
			MrEnclave: *rt.mrEnclave,
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

// BundlePath returns the path to the dynamically generated bundle.
func (rt *Runtime) BundlePath() string {
	return filepath.Join(rt.dir.String(), "bundle.orc")
}

// RefreshRuntimeBundle makes sure the generated runtime bundle is refreshed.
func (rt *Runtime) RefreshRuntimeBundle() error {
	fn := rt.BundlePath()

	// Remove the generated bundle (if any).
	if err := os.Remove(fn); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	rt.bundle = nil
	rt.mrEnclave = nil

	// Generate a fresh bundle.
	_, err := rt.ToRuntimeBundle()
	return err
}

// ToRuntimeBundle serializes the runtime to disk and returns the bundle.
func (rt *Runtime) ToRuntimeBundle() (*bundle.Bundle, error) {
	fn := rt.BundlePath()
	switch _, err := os.Stat(fn); err {
	case nil:
		// Skip re-serializing the bundle, and just open it.
		// This will happen on tests where the network gets restarted.
		if rt.bundle == nil {
			var (
				bnd       *bundle.Bundle
				mrEnclave *sgx.MrEnclave
			)
			if bnd, err = bundle.Open(fn); err != nil {
				return nil, fmt.Errorf("oasis/runtime: failed to open existing bundle: %w", err)
			}
			if rt.teeHardware != node.TEEHardwareInvalid {
				if mrEnclave, err = bnd.MrEnclave(); err != nil {
					return nil, fmt.Errorf("oasis/runtime: failed to derive MRENCLAVE: %w", err)
				}

				rt.descriptor.Version.TEE = cbor.Marshal(node.SGXConstraints{
					Enclaves: []sgx.EnclaveIdentity{
						{
							MrEnclave: *mrEnclave,
							MrSigner:  *rt.mrSigner,
						},
					},
				})
			}
			rt.bundle = bnd
			rt.mrEnclave = mrEnclave
		}

		return rt.bundle, nil
	default:
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("oasis/runtime: failed to stat bundle: %w", err)
		}
	}

	const (
		elfBin = "runtime.elf"
		sgxBin = "runtime.sgx"
	)

	bnd := &bundle.Bundle{
		Manifest: &bundle.Manifest{
			Name:       "test-runtime",
			ID:         rt.cfgSave.id,
			Version:    rt.cfgSave.version,
			Executable: elfBin,
		},
	}

	// XXX: Figure out what to do with the binary index at some point.
	binBuf, err := os.ReadFile(rt.cfgSave.binaries[node.TEEHardwareInvalid])
	if err != nil {
		return nil, fmt.Errorf("oasis/runtime: failed to read ELF binary: %w", err)
	}
	_ = bnd.Add(elfBin, binBuf)

	var mrEnclave *sgx.MrEnclave
	if rt.teeHardware != node.TEEHardwareInvalid {
		binBuf, err = os.ReadFile(rt.cfgSave.binaries[node.TEEHardwareIntelSGX])
		if err != nil {
			return nil, fmt.Errorf("oasis/runtime: failed to read SGX binary: %w", err)
		}
		bnd.Manifest.SGX = &bundle.SGXMetadata{
			Executable: sgxBin,
		}
		_ = bnd.Add(sgxBin, binBuf)

		mrEnclave, err = bnd.MrEnclave()
		if err != nil {
			return nil, fmt.Errorf("oasis/runtime: failed to derive MRENCLAVE: %w", err)
		}

		rt.descriptor.Version.TEE = cbor.Marshal(node.SGXConstraints{
			Enclaves: []sgx.EnclaveIdentity{
				{
					MrEnclave: *mrEnclave,
					MrSigner:  *rt.mrSigner,
				},
			},
		})
	}

	if err = bnd.Write(fn); err != nil {
		return nil, fmt.Errorf("oasis/runtime: failed to write bundle: %w", err)
	}

	rt.bundle = bnd
	rt.mrEnclave = mrEnclave

	return bnd, nil
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

	rtIndex := len(net.runtimes)
	rtDir, err := net.baseDir.NewSubDir(fmt.Sprintf("runtime-%s-%d", cfg.ID, rtIndex))
	if err != nil {
		net.logger.Error("failed to create runtime subdir",
			"err", err,
		)
		return nil, fmt.Errorf("oasis/runtime: failed to create runtime subdir: %w", err)
	}

	if cfg.Keymanager != nil {
		descriptor.KeyManager = new(common.Namespace)
		*descriptor.KeyManager = cfg.Keymanager.ID()
	}

	rt := &Runtime{
		dir: rtDir,
		cfgSave: runtimeCfgSave{
			id:       cfg.ID,
			version:  cfg.Version,
			binaries: cfg.Binaries,
		},
		kind:               cfg.Kind,
		teeHardware:        cfg.TEEHardware,
		mrSigner:           cfg.MrSigner,
		pruner:             cfg.Pruner,
		excludeFromGenesis: cfg.ExcludeFromGenesis,
		descriptor:         descriptor,
	}

	if _, err := rt.ToRuntimeBundle(); err != nil {
		return nil, err
	}

	// Remove any dynamically generated bundles on cleanup.
	net.env.AddOnCleanup(func() {
		_ = os.Remove(rt.BundlePath())
	})

	// Save runtime descriptor into file.
	rtDescStr, _ := json.Marshal(rt.descriptor)
	path := filepath.Join(rtDir.String(), rtDescriptorFile)
	if err := ioutil.WriteFile(path, rtDescStr, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write runtime descriptor to file: %w", err)
	}

	net.runtimes = append(net.runtimes, rt)

	return rt, nil
}
