// Package cmd implements the commands for the ekiden executable.
package cmd

import (
	"github.com/spf13/cobra"

	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/debug"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/ias"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/node"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/registry"
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

func init() {
	cobra.OnInitialize(cmdCommon.InitConfig)

	cmdCommon.RegisterRootFlags(rootCmd)
	node.RegisterFlags(rootCmd)

	// Register all of the sub-commands.
	for _, v := range []func(*cobra.Command){
		debug.Register,
		ias.Register,
		registry.Register,
		storage.Register,
	} {
		v(rootCmd)
	}
}
