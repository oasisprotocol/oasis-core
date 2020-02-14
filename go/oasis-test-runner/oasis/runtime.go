package oasis

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdRegRt "github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry/runtime"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

const rtDescriptorFile = "runtime_genesis.json"

// Runtime is an Oasis runtime.
type Runtime struct { // nolint: maligned
	dir *env.Dir

	id   common.Namespace
	kind registry.RuntimeKind

	binary      string
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

	Binary       string
	GenesisState string
	GenesisRound uint64

	Executor     registry.ExecutorParameters
	Merge        registry.MergeParameters
	TxnScheduler registry.TxnSchedulerParameters
	Storage      registry.StorageParameters

	AdmissionPolicy registry.RuntimeAdmissionPolicy

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
		ID:              cfg.ID,
		EntityID:        cfg.Entity.entity.ID,
		Kind:            cfg.Kind,
		TEEHardware:     cfg.TEEHardware,
		Executor:        cfg.Executor,
		Merge:           cfg.Merge,
		TxnScheduler:    cfg.TxnScheduler,
		Storage:         cfg.Storage,
		AdmissionPolicy: cfg.AdmissionPolicy,
	}

	rtDir, err := net.baseDir.NewSubDir("runtime-" + cfg.ID.String())
	if err != nil {
		net.logger.Error("failed to create runtime subdir",
			"err", err,
		)
		return nil, errors.Wrap(err, "oasis/runtime: failed to create runtime subdir")
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
	var mrEnclave *sgx.MrEnclave
	if cfg.TEEHardware == node.TEEHardwareIntelSGX {
		if mrEnclave, err = deriveMrEnclave(cfg.Binary); err != nil {
			return nil, err
		}

		args = append(args, []string{
			"--" + cmdRegRt.CfgTEEHardware, cfg.TEEHardware.String(),
			"--" + cmdRegRt.CfgVersionEnclave, mrEnclave.String() + cfg.MrSigner.String(),
		}...)

		descriptor.Version.TEE = cbor.Marshal(registry.VersionInfoIntelSGX{
			Enclaves: []sgx.EnclaveIdentity{
				{MrEnclave: *mrEnclave, MrSigner: *cfg.MrSigner},
			},
		})
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
		return nil, errors.New("invalid admission policy")
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
		return nil, errors.Wrap(err, "oasis/runtime: failed to provision runtime")
	}

	rt := &Runtime{
		dir:                rtDir,
		id:                 cfg.ID,
		kind:               cfg.Kind,
		binary:             cfg.Binary,
		teeHardware:        cfg.TEEHardware,
		mrEnclave:          mrEnclave,
		mrSigner:           cfg.MrSigner,
		pruner:             cfg.Pruner,
		excludeFromGenesis: cfg.ExcludeFromGenesis,
		descriptor:         descriptor,
	}
	net.runtimes = append(net.runtimes, rt)

	return rt, nil
}

func deriveMrEnclave(f string) (*sgx.MrEnclave, error) {
	r, err := os.Open(f)
	if err != nil {
		return nil, errors.Wrap(err, "oasis: failed to open enclave binary")
	}
	defer r.Close()

	var m sgx.MrEnclave
	if err = m.FromSgxs(r); err != nil {
		return nil, err
	}

	return &m, nil
}
