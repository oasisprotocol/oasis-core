package cli

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/genesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/stake"
)

// GenesisHelpers contains the oasis-node genesis CLI helpers.
type GenesisHelpers struct {
	*helpersBase
}

// Check is a wrapper for "genesis check" subcommand.
func (g *GenesisHelpers) Check(
	genesisFilePath string,
) (string, error) {
	g.logger.Info("checking genesis file")

	args := []string{
		"genesis", "check",
		"--" + flags.CfgGenesisFile, genesisFilePath,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + common.CfgDebugAllowTestKeys,
	}

	out, err := g.runSubCommandWithOutput("genesis-check", args)
	if err != nil {
		return "", fmt.Errorf("failed to run 'genesis check': error: %w output: %s", err, out.String())
	}

	return out.String(), nil
}

// Dump is a wrapper for "genesis dump" subcommand.
func (g *GenesisHelpers) Dump(
	genesisFilePath string,
) error {
	g.logger.Info("dumping network state to genesis file")

	args := []string{
		"genesis", "dump",
		"--" + stake.CfgHeight, "0",
		"--" + flags.CfgGenesisFile, genesisFilePath,
		"--" + grpc.CfgAddress, "unix:" + g.cfg.NodeSocketPath,
	}

	if out, err := g.runSubCommandWithOutput("genesis-dump", args); err != nil {
		return fmt.Errorf("failed to run 'genesis dump': error: %w output: %s", err, out.String())
	}

	return nil
}

// Migrate is a wrapper for "genesis migrate" subcommand.
func (g *GenesisHelpers) Migrate(
	genesisFilePath string,
	newGenesisFilePath string,
) error {
	g.logger.Info("migrating genesis file")

	args := []string{
		"genesis", "migrate",
		"--" + flags.CfgGenesisFile, genesisFilePath,
		"--" + genesis.CfgNewGenesisFile, newGenesisFilePath,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + common.CfgDebugAllowTestKeys,
	}

	if out, err := g.runSubCommandWithOutput("genesis-migrate", args); err != nil {
		return fmt.Errorf("failed to run 'genesis migrate': error: %w output: %s", err, out.String())
	}

	return nil
}
