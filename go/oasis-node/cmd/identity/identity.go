// Package identity implements the identity sub-commands.
package identity

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/identity/tendermint"
)

var (
	identityCmd = &cobra.Command{
		Use:   "identity",
		Short: "identity interface utilities",
	}

	identityInitCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize node identity",
		Run:   doNodeInit,
	}

	logger = logging.GetLogger("cmd/identity")
)

func doNodeInit(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory must be set")
		os.Exit(1)
	}

	// Provision the node identity.
	nodeSignerFactory, err := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	if err != nil {
		logger.Error("failed to create identity signer factory",
			"err", err,
		)
		os.Exit(1)
	}
	if _, err = identity.LoadOrGenerate(dataDir, nodeSignerFactory); err != nil {
		logger.Error("failed to load or generate node identity",
			"err", err,
		)
		os.Exit(1)
	}

	fmt.Printf("Generated identity files in: %s\n", dataDir)
}

// Register registers the client sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	tendermint.Register(identityCmd)

	identityInitCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)
	identityCmd.AddCommand(identityInitCmd)

	parentCmd.AddCommand(identityCmd)
}
