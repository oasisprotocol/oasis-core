// Package cmd implements the commands for the oasis-node executable.
package cmd

import (
	"os"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/consensus"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/control"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/genesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/governance"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/ias"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/identity"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/keymanager"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/node"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/signer"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/stake"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/storage"
)

var rootCmd = &cobra.Command{
	Use:     "oasis-node",
	Short:   "Oasis Node",
	Version: version.SoftwareVersion,
	Run:     node.Run,
}

// RootCommand returns the root (top level) cobra.Command.
func RootCommand() *cobra.Command {
	return rootCmd
}

// Execute spawns the main entry point after handling the config file
// and command line arguments.
func Execute() {
	// Only the owner should have read/write/execute permissions for
	// anything created by the oasis-node binary.
	syscall.Umask(0o077)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initVersions() {
	cobra.AddTemplateFunc("nodeVersion", func() interface{} { return version.Versions })

	rootCmd.SetVersionTemplate(`Software version: {{.Version}}
{{- with nodeVersion }}
Consensus:
  Consensus protocol version: {{ .ConsensusProtocol }}
Runtime:
  Host protocol version:      {{ .RuntimeHostProtocol }}
  Committee protocol version: {{ .RuntimeCommitteeProtocol }}
Go toolchain version: {{ .Toolchain }}
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
		governance.Register,
		ias.Register,
		identity.Register,
		keymanager.Register,
		registry.Register,
		signer.Register,
		stake.Register,
		storage.Register,
		consensus.Register,
		node.Register,
	} {
		v(rootCmd)
	}
}
