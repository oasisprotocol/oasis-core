// Package signer registers all subcommands needed by specific signers
package signer

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/signer/ledger"
)

var (
	signerCmd = &cobra.Command{
		Use:   "signer",
		Short: "signer backend utilities",
	}
)

func Register(parentCmd *cobra.Command) {
	for _, v := range []func(*cobra.Command){
		ledger.Register,
	} {
		v(signerCmd)
	}

	parentCmd.AddCommand(signerCmd)
}
