package cli

import (
	"fmt"
	"strconv"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/node"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdRegRt "github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry/runtime"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

// RegistryHelpers contains the oasis-node registry CLI helpers.
type RegistryHelpers struct {
	*helpersBase
}

// GenerateRegisterRuntimeTx is a wrapper for "registry runtime gen_register" subcommand.
func (r *RegistryHelpers) GenerateRegisterRuntimeTx(
	nonce uint64,
	runtime registry.Runtime,
	txPath, genesisStateFile string,
) error {
	r.logger.Info("generating register runtime tx")

	// Generate a runtime register transaction file with debug test entity.
	args := []string{
		"registry", "runtime", "gen_register",
		"--" + cmdRegRt.CfgID, runtime.ID.String(),
		"--" + cmdRegRt.CfgTEEHardware, runtime.TEEHardware.String(),
		"--" + cmdRegRt.CfgKind, runtime.Kind.String(),
		"--" + cmdRegRt.CfgVersion, runtime.Version.Version.String(),
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(0), // TODO: Make fee configurable.
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(10), // TODO: Make fee configurable.
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + cmdCommon.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugTestEntity,
		"--" + flags.CfgGenesisFile, r.net.GenesisPath(),
	}

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
			"--"+cmdRegRt.CfgComputeGroupSize, strconv.FormatUint(runtime.Compute.GroupSize, 10),
			"--"+cmdRegRt.CfgComputeGroupBackupSize, strconv.FormatUint(runtime.Compute.GroupBackupSize, 10),
			"--"+cmdRegRt.CfgComputeAllowedStragglers, strconv.FormatUint(runtime.Compute.AllowedStragglers, 10),
			"--"+cmdRegRt.CfgComputeRoundTimeout, runtime.Compute.RoundTimeout.String(),
			"--"+cmdRegRt.CfgMergeGroupSize, strconv.FormatUint(runtime.Merge.GroupSize, 10),
			"--"+cmdRegRt.CfgMergeGroupBackupSize, strconv.FormatUint(runtime.Merge.GroupBackupSize, 10),
			"--"+cmdRegRt.CfgMergeAllowedStragglers, strconv.FormatUint(runtime.Merge.AllowedStragglers, 10),
			"--"+cmdRegRt.CfgMergeRoundTimeout, runtime.Merge.RoundTimeout.String(),
			"--"+cmdRegRt.CfgStorageGroupSize, strconv.FormatUint(runtime.Storage.GroupSize, 10),
			"--"+cmdRegRt.CfgTxnSchedulerGroupSize, strconv.FormatUint(runtime.TxnScheduler.GroupSize, 10),
			"--"+cmdRegRt.CfgTxnSchedulerAlgorithm, runtime.TxnScheduler.Algorithm,
			"--"+cmdRegRt.CfgTxnSchedulerBatchFlushTimeout, runtime.TxnScheduler.BatchFlushTimeout.String(),
			"--"+cmdRegRt.CfgTxnSchedulerMaxBatchSize, strconv.FormatUint(runtime.TxnScheduler.MaxBatchSize, 10),
			"--"+cmdRegRt.CfgTxnSchedulerMaxBatchSizeBytes, strconv.FormatUint(runtime.TxnScheduler.MaxBatchSizeBytes, 10),
		)
	}
	if runtime.KeyManager != nil {
		args = append(args, "--"+cmdRegRt.CfgKeyManager, runtime.KeyManager.String())
	}
	if err := r.runSubCommand("registry-runtime-gen_register", args); err != nil {
		return fmt.Errorf("failed to generate register runtime tx: %w", err)
	}

	return nil
}
