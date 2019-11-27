package e2e

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
)

// submitTx is a wrapper for consensus submit_tx command.
func submitTx(childEnv *env.Env, txPath string, logger *logging.Logger, socketPath string, nodeBinary string) error {
	logger.Info("submitting tx", consensus.CfgTxFile, txPath)
	args := []string{
		"consensus", "submit_tx",
		"--" + consensus.CfgTxFile, txPath,
		"--" + grpc.CfgAddress, "unix:" + socketPath,
		"--" + common.CfgDebugAllowTestKeys,
	}
	if err := runSubCommand(childEnv, "submit", nodeBinary, args); err != nil {
		return fmt.Errorf("failed to submit tx: %w", err)
	}
	return nil
}
