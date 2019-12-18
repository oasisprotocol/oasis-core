// Package cmd implements the commands for Urkel interoperability test helpers.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/common/version"
)

var (
	rootCmd = &cobra.Command{
		Use:     "urkel-test-helpers",
		Short:   "Urkel interoperability test helpers",
		Version: version.SoftwareVersion,
	}
)

// RootCommand returns the root (top level) cobra.Command.
func RootCommand() *cobra.Command {
	return rootCmd
}

// Execute spawns the main entry point after handling the command line arguments.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

func init() {
	// Register all of the sub-commands.
	RegisterProtoServer(rootCmd)
}
