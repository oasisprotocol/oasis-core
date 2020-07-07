package cli

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/consensus"
)

// ConsensusHelpers contains the oasis-node consensus CLI helpers.
type ConsensusHelpers struct {
	*helpersBase
}

// SubmitTx is a wrapper for "consensus submit_tx" subcommand.
func (c *ConsensusHelpers) SubmitTx(txPath string) error {
	c.logger.Info("submitting tx", consensus.CfgTxFile, txPath)

	args := []string{
		"consensus", "submit_tx",
		"--" + consensus.CfgTxFile, txPath,
		"--" + grpc.CfgAddress, "unix:" + c.cfg.NodeSocketPath,
		"--" + common.CfgDebugAllowTestKeys,
	}
	if err := c.runSubCommand("consensus-submit_tx", args); err != nil {
		return fmt.Errorf("failed to submit tx: %w", err)
	}
	return nil
}

// EstimateGas is a wrapper for "consensus estimate_gas" subcommand.
func (c *ConsensusHelpers) EstimateGas(txPath string, signerPub signature.PublicKey) (transaction.Gas, error) {
	c.logger.Info("estimating gas", consensus.CfgTxFile, txPath)

	signerPubStr, err := signerPub.MarshalText()
	if err != nil {
		return 0, fmt.Errorf("marshal signerPub: %w", err)
	}
	args := []string{
		"consensus", "estimate_gas",
		"--" + consensus.CfgTxFile, txPath,
		"--" + grpc.CfgAddress, "unix:" + c.cfg.NodeSocketPath,
		"--" + cmdConsensus.CfgSignerPub, string(signerPubStr),
	}
	out, err := c.runSubCommandWithOutput("consensus-estimate_gas", args)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate gas: error: %w output: %s", err, out.String())
	}
	gasS := out.String()
	var gas transaction.Gas
	if _, err = fmt.Sscan(gasS, &gas); err != nil {
		return 0, fmt.Errorf("failed to parse output: error: %w output: %s", err, gasS)
	}
	return gas, nil
}
