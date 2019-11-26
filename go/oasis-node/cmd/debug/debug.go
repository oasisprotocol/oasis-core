// Package debug implements various sub-commands useful for debugging.
package debug

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/byzantine"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/dummy"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/storage"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/tendermint"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "debug utilities",
}

// Register registers the debug sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	dummy.Register(debugCmd)
	storage.Register(debugCmd)
	tendermint.Register(debugCmd)
	byzantine.Register(debugCmd)

	parentCmd.AddCommand(debugCmd)
}
