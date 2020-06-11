package oasis

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdRegRt "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/runtime"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const rtDescriptorFile = "runtime_genesis.json"

// Runtime is an Oasis runtime.
type Runtime struct { // nolint: maligned
	dir *env.Dir

	id   common.Namespace
	kind registry.RuntimeKind

	binaries    []string
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

	Binaries     []string
	GenesisState string
	GenesisRound uint64

	Executor     registry.ExecutorParameters
	Merge        registry.MergeParameters
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
		DescriptorVersion: registry.LatestRuntimeDescriptorVersion,
		ID:                cfg.ID,
		EntityID:          cfg.Entity.entity.ID,
		Kind:              cfg.Kind,
		TEEHardware:       cfg.TEEHardware,
		Executor:          cfg.Executor,
		Merge:             cfg.Merge,
		TxnScheduler:      cfg.TxnScheduler,
		Storage:           cfg.Storage,
		AdmissionPolicy:   cfg.AdmissionPolicy,
		Staking:           cfg.Staking,
	}

	rtDir, err := net.baseDir.NewSubDir("runtime-" + cfg.ID.String())
	if err != nil {
		net.logger.Error("failed to create runtime subdir",
			"err", err,
		)
		return nil, fmt.Errorf("oasis/runtime: failed to create runtime subdir: %w", err)
	}

	args := []string{
		"registry", "runtime", "init_genesis",
		"--" + cmdCommon.CfgDataDir, rtDir.String(),
		"--" + cmdRegRt.CfgID, cfg.ID.String(),
		"--" + cmdRegRt.CfgKind, cfg.Kind.String(),
	}
	if cfg.Kind == registry.KindCompute {
		args = append(args, []string{
			"--" + cmdRegRt.CfgExecutorGroupSize, strconv.FormatUint(cfg.Executor.GroupSize, 10),
			"--" + cmdRegRt.CfgExecutorGroupBackupSize, strconv.FormatUint(cfg.Executor.GroupBackupSize, 10),
			"--" + cmdRegRt.CfgExecutorAllowedStragglers, strconv.FormatUint(cfg.Executor.AllowedStragglers, 10),
			"--" + cmdRegRt.CfgExecutorRoundTimeout, cfg.Executor.RoundTimeout.String(),
			"--" + cmdRegRt.CfgMergeGroupSize, strconv.FormatUint(cfg.Merge.GroupSize, 10),
			"--" + cmdRegRt.CfgMergeGroupBackupSize, strconv.FormatUint(cfg.Merge.GroupBackupSize, 10),
			"--" + cmdRegRt.CfgMergeAllowedStragglers, strconv.FormatUint(cfg.Merge.AllowedStragglers, 10),
			"--" + cmdRegRt.CfgMergeRoundTimeout, cfg.Merge.RoundTimeout.String(),
			"--" + cmdRegRt.CfgTxnSchedulerGroupSize, strconv.FormatUint(cfg.TxnScheduler.GroupSize, 10),
			"--" + cmdRegRt.CfgTxnSchedulerMaxBatchSize, strconv.FormatUint(cfg.TxnScheduler.MaxBatchSize, 10),
			"--" + cmdRegRt.CfgTxnSchedulerMaxBatchSizeBytes, strconv.FormatUint(cfg.TxnScheduler.MaxBatchSizeBytes, 10),
			"--" + cmdRegRt.CfgTxnSchedulerAlgorithm, cfg.TxnScheduler.Algorithm,
			"--" + cmdRegRt.CfgTxnSchedulerBatchFlushTimeout, cfg.TxnScheduler.BatchFlushTimeout.String(),
			"--" + cmdRegRt.CfgStorageGroupSize, strconv.FormatUint(cfg.Storage.GroupSize, 10),
			"--" + cmdRegRt.CfgStorageMaxApplyWriteLogEntries, strconv.FormatUint(cfg.Storage.MaxApplyWriteLogEntries, 10),
			"--" + cmdRegRt.CfgStorageMaxApplyOps, strconv.FormatUint(cfg.Storage.MaxApplyOps, 10),
			"--" + cmdRegRt.CfgStorageMaxMergeRoots, strconv.FormatUint(cfg.Storage.MaxMergeRoots, 10),
			"--" + cmdRegRt.CfgStorageMaxMergeOps, strconv.FormatUint(cfg.Storage.MaxMergeOps, 10),
			"--" + cmdRegRt.CfgStorageCheckpointInterval, strconv.FormatUint(cfg.Storage.CheckpointInterval, 10),
			"--" + cmdRegRt.CfgStorageCheckpointNumKept, strconv.FormatUint(cfg.Storage.CheckpointNumKept, 10),
			"--" + cmdRegRt.CfgStorageCheckpointChunkSize, strconv.FormatUint(cfg.Storage.CheckpointChunkSize, 10),
		}...)

		if cfg.GenesisState != "" {
			args = append(args,
				"--"+cmdRegRt.CfgGenesisRound, strconv.FormatUint(cfg.GenesisRound, 10),
				"--"+cmdRegRt.CfgGenesisState, cfg.GenesisState,
			)

			descriptor.Genesis.Round = cfg.GenesisRound
			// TODO: Support genesis state.
		}
	}
	var mrEnclaves []*sgx.MrEnclave
	if cfg.TEEHardware == node.TEEHardwareIntelSGX {
		enclaveIdentities := []sgx.EnclaveIdentity{}
		for _, binary := range cfg.Binaries {
			var mrEnclave *sgx.MrEnclave
			if mrEnclave, err = deriveMrEnclave(binary); err != nil {
				return nil, err
			}
			enclaveIdentities = append(enclaveIdentities, sgx.EnclaveIdentity{MrEnclave: *mrEnclave, MrSigner: *cfg.MrSigner})
			args = append(args, []string{
				"--" + cmdRegRt.CfgVersionEnclave, mrEnclave.String() + cfg.MrSigner.String(),
			}...)
			mrEnclaves = append(mrEnclaves, mrEnclave)
		}
		descriptor.Version.TEE = cbor.Marshal(registry.VersionInfoIntelSGX{
			Enclaves: enclaveIdentities,
		})
		args = append(args, []string{
			"--" + cmdRegRt.CfgTEEHardware, cfg.TEEHardware.String(),
		}...)
	}
	if cfg.Keymanager != nil {
		args = append(args, []string{
			"--" + cmdRegRt.CfgKeyManager, cfg.Keymanager.id.String(),
		}...)

		descriptor.KeyManager = new(common.Namespace)
		*descriptor.KeyManager = cfg.Keymanager.id
	}
	if cfg.AdmissionPolicy.AnyNode != nil {
		args = append(args,
			"--"+cmdRegRt.CfgAdmissionPolicy, cmdRegRt.AdmissionPolicyNameAnyNode,
		)
	} else if cfg.AdmissionPolicy.EntityWhitelist != nil {
		args = append(args,
			"--"+cmdRegRt.CfgAdmissionPolicy, cmdRegRt.AdmissionPolicyNameEntityWhitelist,
		)
		for e := range cfg.AdmissionPolicy.EntityWhitelist.Entities {
			args = append(args,
				"--"+cmdRegRt.CfgAdmissionPolicyEntityWhitelist, e.String(),
			)
		}
	} else {
		return nil, fmt.Errorf("invalid admission policy")
	}

	for kind, value := range cfg.Staking.Thresholds {
		kindRaw, _ := kind.MarshalText()
		valueRaw, _ := value.MarshalText()

		args = append(args,
			"--"+cmdRegRt.CfgStakingThreshold, fmt.Sprintf("%s=%s", string(kindRaw), string(valueRaw)),
		)
	}

	args = append(args, cfg.Entity.toGenesisArgs()...)

	w, err := rtDir.NewLogWriter("provision.log")
	if err != nil {
		return nil, err
	}
	defer w.Close()

	if err = net.runNodeBinary(w, args...); err != nil {
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
		genesisState:       cfg.GenesisState,
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
