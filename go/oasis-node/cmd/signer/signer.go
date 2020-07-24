// Package signer registers all subcommands needed by specific signers
package signer

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
)

var (
	signerCmd = &cobra.Command{
		Use:   "signer",
		Short: "signer backend utilities",
	}

	exportCmd = &cobra.Command{
		Use:   "export",
		Short: "export the public key from signer as an empty entity",
		Run:   doExport,
	}

	logger = logging.GetLogger("cmd/signer")
)

func doExport(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}
	entityDir, err := cmdSigner.CLIDirOrPwd()
	if err != nil {
		logger.Error("failed to retrieve signer dir",
			"err", err,
		)
		os.Exit(1)
	}
	if err := cmdCommon.ExportEntity(cmdSigner.Backend(), entityDir); err != nil {
		logger.Error("failed to export entity",
			"err", err,
		)
		os.Exit(1)
	}
}

func Register(parentCmd *cobra.Command) {
	exportCmd.Flags().AddFlagSet(cmdSigner.Flags)
	exportCmd.Flags().AddFlagSet(cmdSigner.CLIFlags)

	signerCmd.AddCommand(exportCmd)
	parentCmd.AddCommand(signerCmd)
}
