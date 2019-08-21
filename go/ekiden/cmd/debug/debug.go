// Package debug implements various sub-commands useful for debugging.
package debug

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/ekiden/cmd/debug/byzantine"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/debug/client"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/debug/dummy"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/debug/roothash"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/debug/tendermint"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "debug utilities",
}

// Register registers the debug sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	client.Register(debugCmd)
	dummy.Register(debugCmd)
	roothash.Register(debugCmd)
	tendermint.Register(debugCmd)
	byzantine.Register(debugCmd)

	parentCmd.AddCommand(debugCmd)
}
