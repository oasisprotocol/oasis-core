package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdKM "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/keymanager"
)

// KeymanagerHelpers contains the oasis-node keymanager CLI helpers.
type KeymanagerHelpers struct {
	*helpersBase
}

// InitPolicy generates the KM policy file.
func (k *KeymanagerHelpers) InitPolicy(runtimeID common.Namespace, serial uint32, policies map[sgx.EnclaveIdentity]*keymanager.EnclavePolicySGX, polPath string) error {
	k.logger.Info("initing KM policy",
		"policy_path", polPath,
		"serial", serial,
		"num_policies", len(policies),
	)

	args := []string{
		"keymanager", "init_policy",
		"--" + cmdKM.CfgPolicyFile, polPath,
		"--" + cmdKM.CfgPolicyID, runtimeID.String(),
		"--" + cmdKM.CfgPolicySerial, strconv.FormatUint(uint64(serial), 10),
	}
	for enclave, policy := range policies {
		args = append(args, "--"+cmdKM.CfgPolicyEnclaveID)
		args = append(args, enclave.String())
		if len(policy.MayQuery) > 0 {
			for rtID, encIDs := range policy.MayQuery {
				args = append(args, "--"+cmdKM.CfgPolicyMayQuery)
				var encIDstrs []string
				for _, eid := range encIDs {
					encIDstrs = append(encIDstrs, eid.String())
				}
				args = append(args, rtID.String()+"="+strings.Join(encIDstrs, ","))
			}
		}
		if len(policy.MayReplicate) > 0 {
			args = append(args, "--"+cmdKM.CfgPolicyMayReplicate)
			var encIDstrs []string
			for _, eid := range policy.MayReplicate {
				encIDstrs = append(encIDstrs, eid.String())
			}
			args = append(args, strings.Join(encIDstrs, ","))
		}
	}
	if err := k.runSubCommand("keymanager-init_policy", args); err != nil {
		return fmt.Errorf("failed to init KM policy: %w", err)
	}
	return nil
}

// SignPolicy signs the KM policy file using the given test key ("1", "2", or "3").
func (k *KeymanagerHelpers) SignPolicy(testKey, polPath, polSigPath string) error {
	k.logger.Info("signing KM policy",
		"policy_path", polPath,
		"policy_signature_path", polSigPath,
		"test_key", testKey,
	)

	args := []string{
		"keymanager", "sign_policy",
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + cmdCommon.CfgDebugAllowTestKeys,
		"--" + cmdKM.CfgPolicyFile, polPath,
		"--" + cmdKM.CfgPolicySigFile, polSigPath,
		"--" + cmdKM.CfgPolicyTestKey, testKey,
	}
	if err := k.runSubCommand("keymanager-sign_policy", args); err != nil {
		return fmt.Errorf("failed to sign KM policy: %w", err)
	}
	return nil
}

// GenUpdate generates the update KM policy transaction.
func (k *KeymanagerHelpers) GenUpdate(nonce uint64, polPath string, polSigPaths []string, txPath string) error {
	k.logger.Info("generating KM policy update",
		"policy_path", polPath,
		"policy_signature_paths", polSigPaths,
		"transaction_path", txPath,
	)

	args := []string{
		"keymanager", "gen_update",
		"--" + cmdConsensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + cmdConsensus.CfgTxFile, txPath,
		"--" + cmdConsensus.CfgTxFeeAmount, strconv.Itoa(0), // TODO: Make fee configurable.
		"--" + cmdConsensus.CfgTxFeeGas, strconv.Itoa(10000), // TODO: Make fee configurable.
		"--" + cmdKM.CfgPolicyFile, polPath,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + cmdCommon.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugTestEntity,
		"--" + flags.CfgGenesisFile, k.cfg.GenesisFile,
	}
	for _, sigPath := range polSigPaths {
		args = append(args, "--"+cmdKM.CfgPolicySigFile, sigPath)
	}
	if err := k.runSubCommand("keymanager-gen_update", args); err != nil {
		return fmt.Errorf("failed to generate KM update transaction: %w", err)
	}
	return nil
}
