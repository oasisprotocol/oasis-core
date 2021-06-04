// Package debug implements various sub-commands useful for debugging.
package debug

import (
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/beacon"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/byzantine"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/consim"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/control"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/dumpdb"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/fixgenesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/storage"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/txsource"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "debug utilities",
}

// Register registers the debug sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	storage.Register(debugCmd)
	byzantine.Register(debugCmd)
	txsource.Register(debugCmd)
	fixgenesis.Register(debugCmd)
	control.Register(debugCmd)
	consim.Register(debugCmd)
	dumpdb.Register(debugCmd)
	beacon.Register(debugCmd)

	parentCmd.AddCommand(debugCmd)
}
