// Package cmd implements the commands for the oasis-node executable.
package cmd

import (
	"syscall"

	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/common/version"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/consensus"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/control"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/genesis"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/ias"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/keymanager"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/node"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/stake"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/storage"
)

var (
	rootCmd = &cobra.Command{
		Use:     "oasis-node",
		Short:   "Oasis Node",
		Version: "0.2.0-alpha" + version.Build,
		Run:     node.Run,
	}
)

// RootCommand returns the root (top level) cobra.Command.
func RootCommand() *cobra.Command {
	return rootCmd
}

// Execute spawns the main entry point after handling the config file
// and command line arguments.
func Execute() {
	// Only the owner should have read/write/execute permissions for
	// anything created by the oasis-node binary.
	syscall.Umask(0077)

	if err := rootCmd.Execute(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}
}

func initVersions() {
	cobra.AddTemplateFunc("nodeVersion", func() interface{} { return version.Versions })

	rootCmd.SetVersionTemplate(`Software version: {{.Version}}
{{- with nodeVersion }}
Runtime protocol version: {{ .RuntimeProtocol }}
Consensus protocol version: {{ .ConsensusProtocol }}
Committee protocol version: {{ .CommitteeProtocol }}
Tendermint core version: {{ .Tendermint }}
ABCI library version: {{ .ABCI }}
{{ end -}}
`)
}

func init() {
	cobra.OnInitialize(cmdCommon.InitConfig)
	initVersions()

	rootCmd.PersistentFlags().AddFlagSet(cmdCommon.RootFlags)
	rootCmd.Flags().AddFlagSet(node.Flags)

	// Register all of the sub-commands.
	for _, v := range []func(*cobra.Command){
		control.Register,
		debug.Register,
		genesis.Register,
		ias.Register,
		keymanager.Register,
		registry.Register,
		stake.Register,
		storage.Register,
		consensus.Register,
	} {
		v(rootCmd)
	}
}
