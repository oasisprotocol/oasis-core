// Package cmd implements the commands for the ekiden executable.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/version"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/debug"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/genesis"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/ias"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/keymanager"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/node"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/registry"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/stake"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/storage"
)

var (
	rootCmd = &cobra.Command{
		Use:     "ekiden",
		Short:   "Ekiden",
		Version: "0.2.0-alpha",
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
	if err := rootCmd.Execute(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}
}

func initVersions() {
	cobra.AddTemplateFunc("ekidenVersion", func() interface{} { return version.Versions })

	rootCmd.SetVersionTemplate(`Software version: {{.Version}}
{{- with ekidenVersion }}
Runtime protocol version: {{ .RuntimeProtocol }}
Backend protocol version: {{ .BackendProtocol }}
Compute committee protocol version: {{ .ComputeCommitteeProtocol }}
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
		debug.Register,
		genesis.Register,
		ias.Register,
		keymanager.Register,
		registry.Register,
		stake.Register,
		storage.Register,
	} {
		v(rootCmd)
	}
}
