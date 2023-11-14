// Package sgx implements various sgx-related sub-commands.
package sgx

import (
	"github.com/spf13/cobra"

	platformData "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/sgx/platform-data"
)

var sgxCmd = &cobra.Command{
	Use:   "sgx",
	Short: "sgx utilities",
}

// Register registers the sgx sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	platformData.Register(sgxCmd)

	parentCmd.AddCommand(sgxCmd)
}
