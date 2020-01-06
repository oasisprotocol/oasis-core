package cli

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
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
		"--" + grpc.CfgAddress, "unix:" + c.net.Validators()[0].SocketPath(),
		"--" + common.CfgDebugAllowTestKeys,
	}
	if err := c.runSubCommand("consensus-submit_tx", args); err != nil {
		return fmt.Errorf("failed to submit tx: %w", err)
	}
	return nil
}
