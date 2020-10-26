package cli

import (
	"fmt"
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdRegRt "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/runtime"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// RegistryHelpers contains the oasis-node registry CLI helpers.
type RegistryHelpers struct {
	*helpersBase
}

func (r *RegistryHelpers) runRegistryRuntimeSubcommand(
	cmd string,
	runtime registry.Runtime,
	genesisStateFile string,
	extraArgs ...string,
) error {
	args := []string{
		"registry", "runtime", cmd,
		"--" + cmdRegRt.CfgID, runtime.ID.String(),
		"--" + cmdRegRt.CfgTEEHardware, runtime.TEEHardware.String(),
		"--" + cmdRegRt.CfgKind, runtime.Kind.String(),
		"--" + cmdRegRt.CfgVersion, runtime.Version.Version.String(),
	}
	args = append(args, extraArgs...)

	switch runtime.TEEHardware {
	case node.TEEHardwareInvalid:
	case node.TEEHardwareIntelSGX:
		var versionIntelSGX registry.VersionInfoIntelSGX
		if err := cbor.Unmarshal(runtime.Version.TEE, &versionIntelSGX); err != nil {
			return fmt.Errorf("failed to unmarshal Intel SGX TEE version: %w", err)
		}

		for _, e := range versionIntelSGX.Enclaves {
			args = append(args,
				"--"+cmdRegRt.CfgVersionEnclave, e.String(),
			)
		}
	default:
		return fmt.Errorf("unsupported TEE hardware: %s", runtime.TEEHardware)
	}

	if runtime.Kind == registry.KindCompute {
		args = append(args,
			"--"+cmdRegRt.CfgGenesisState, genesisStateFile,
			"--"+cmdRegRt.CfgGenesisRound, strconv.FormatUint(runtime.Genesis.Round, 10),
			"--"+cmdRegRt.CfgExecutorGroupSize, strconv.FormatUint(runtime.Executor.GroupSize, 10),
			"--"+cmdRegRt.CfgExecutorGroupBackupSize, strconv.FormatUint(runtime.Executor.GroupBackupSize, 10),
			"--"+cmdRegRt.CfgExecutorAllowedStragglers, strconv.FormatUint(runtime.Executor.AllowedStragglers, 10),
			"--"+cmdRegRt.CfgExecutorRoundTimeout, strconv.FormatInt(runtime.Executor.RoundTimeout, 10),
			"--"+cmdRegRt.CfgExecutorMaxMessages, strconv.FormatUint(uint64(runtime.Executor.MaxMessages), 10),
			"--"+cmdRegRt.CfgStorageGroupSize, strconv.FormatUint(runtime.Storage.GroupSize, 10),
			"--"+cmdRegRt.CfgStorageMinWriteReplication, strconv.FormatUint(runtime.Storage.MinWriteReplication, 10),
			"--"+cmdRegRt.CfgStorageMaxApplyWriteLogEntries, strconv.FormatUint(runtime.Storage.MaxApplyWriteLogEntries, 10),
			"--"+cmdRegRt.CfgStorageMaxApplyOps, strconv.FormatUint(runtime.Storage.MaxApplyOps, 10),
			"--"+cmdRegRt.CfgStorageCheckpointInterval, strconv.FormatUint(runtime.Storage.CheckpointInterval, 10),
			"--"+cmdRegRt.CfgStorageCheckpointNumKept, strconv.FormatUint(runtime.Storage.CheckpointNumKept, 10),
			"--"+cmdRegRt.CfgStorageCheckpointChunkSize, strconv.FormatUint(runtime.Storage.CheckpointChunkSize, 10),
			"--"+cmdRegRt.CfgTxnSchedulerAlgorithm, runtime.TxnScheduler.Algorithm,
			"--"+cmdRegRt.CfgTxnSchedulerBatchFlushTimeout, runtime.TxnScheduler.BatchFlushTimeout.String(),
			"--"+cmdRegRt.CfgTxnSchedulerMaxBatchSize, strconv.FormatUint(runtime.TxnScheduler.MaxBatchSize, 10),
			"--"+cmdRegRt.CfgTxnSchedulerMaxBatchSizeBytes, strconv.FormatUint(runtime.TxnScheduler.MaxBatchSizeBytes, 10),
			"--"+cmdRegRt.CfgTxnSchedulerProposerTimeout, strconv.FormatInt(runtime.TxnScheduler.ProposerTimeout, 10),
		)
	}
	if runtime.KeyManager != nil {
		args = append(args, "--"+cmdRegRt.CfgKeyManager, runtime.KeyManager.String())
	}

	if runtime.AdmissionPolicy.AnyNode != nil {
		args = append(args,
			"--"+cmdRegRt.CfgAdmissionPolicy, cmdRegRt.AdmissionPolicyNameAnyNode,
		)
	} else if runtime.AdmissionPolicy.EntityWhitelist != nil {
		args = append(args,
			"--"+cmdRegRt.CfgAdmissionPolicy, cmdRegRt.AdmissionPolicyNameEntityWhitelist,
		)
		for e := range runtime.AdmissionPolicy.EntityWhitelist.Entities {
			args = append(args,
				"--"+cmdRegRt.CfgAdmissionPolicyEntityWhitelist, e.String(),
			)
		}
	} else {
		return fmt.Errorf("invalid admission policy")
	}

	for kind, value := range runtime.Staking.Thresholds {
		kindRaw, _ := kind.MarshalText()
		valueRaw, _ := value.MarshalText()

		args = append(args,
			"--"+cmdRegRt.CfgStakingThreshold, fmt.Sprintf("%s=%s", string(kindRaw), string(valueRaw)),
		)
	}

	if out, err := r.runSubCommandWithOutput("registry-runtime-"+cmd, args); err != nil {
		return fmt.Errorf("failed to run 'registry runtime %s': error: %w output: %s", cmd, err, out.String())
	}

	return nil
}

// GenerateRegisterRuntimeTx is a wrapper for "registry runtime gen_register" subcommand.
func (r *RegistryHelpers) GenerateRegisterRuntimeTx(
	nonce uint64,
	runtime registry.Runtime,
	txPath, genesisStateFile string,
) error {
	r.logger.Info("generating register runtime tx")

	// Generate a runtime register transaction file with debug test entity.
	return r.runRegistryRuntimeSubcommand("gen_register", runtime, genesisStateFile,
		"--"+consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--"+consensus.CfgTxFile, txPath,
		"--"+consensus.CfgTxFeeAmount, strconv.Itoa(0), // TODO: Make fee configurable.
		"--"+consensus.CfgTxFeeGas, strconv.Itoa(10000), // TODO: Make fee configurable.
		"--"+flags.CfgDebugDontBlameOasis,
		"--"+cmdCommon.CfgDebugAllowTestKeys,
		"--"+flags.CfgDebugTestEntity,
		"--"+flags.CfgGenesisFile, r.cfg.GenesisFile,
	)
}

// InitGenesis is a wrapper for "registry runtime init_genesis" subcommand.
func (r *RegistryHelpers) InitGenesis(runtime registry.Runtime, genesisStateFile string, extraArgs ...string) error {
	return r.runRegistryRuntimeSubcommand("init_genesis", runtime, genesisStateFile, extraArgs...)
}
