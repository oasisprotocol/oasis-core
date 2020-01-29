// Package debug implements various sub-commands useful for debugging.
package debug

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/byzantine"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/fixgenesis"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/storage"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/tendermint"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/txsource"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "debug utilities",
}

// Register registers the debug sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	storage.Register(debugCmd)
	tendermint.Register(debugCmd)
	byzantine.Register(debugCmd)
	txsource.Register(debugCmd)
	fixgenesis.Register(debugCmd)

	parentCmd.AddCommand(debugCmd)
}
