package cli

import (
	"fmt"
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
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
func (c *ConsensusHelpers) EstimateGas(txPath string) (transaction.Gas, error) {
	c.logger.Info("estimating gas", consensus.CfgTxFile, txPath)

	args := []string{
		"consensus", "estimate_gas",
		"--" + consensus.CfgTxFile, txPath,
		"--" + grpc.CfgAddress, "unix:" + c.cfg.NodeSocketPath,
		"--" + common.CfgDebugAllowTestKeys,
	}
	out, err := c.runSubCommandWithOutput("consensus-estimate_gas", args)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate gas: %w stderr [%s]", err, out.String())
	}
	gasS := out.String()
	gasU, err := strconv.ParseUint(gasS, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse output %s: %w", gasS, err)
	}
	return transaction.Gas(gasU), nil
}
