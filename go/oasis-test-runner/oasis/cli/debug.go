package cli

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/fixgenesis"
)

// DebugHelpers contains the oasis-node debug CLI helpers.
type DebugHelpers struct {
	*helpersBase
}

// FixGenesis is a wrapper for "debug fix-genesis" subcommand.
func (d *DebugHelpers) FixGenesis(
	genesisFilePath string,
	fixedGenesisFilePath string,
) error {
	d.logger.Info("fixing genesis file")

	args := []string{
		"debug", "fix-genesis",
		"--" + flags.CfgGenesisFile, genesisFilePath,
		"--" + fixgenesis.CfgNewGenesisFile, fixedGenesisFilePath,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + common.CfgDebugAllowTestKeys,
	}

	if out, err := d.runSubCommandWithOutput("debug-fix-genesis", args); err != nil {
		return fmt.Errorf("failed to run 'debug fix-genesis': error: %w output: %s", err, out.String())
	}

	return nil
}
