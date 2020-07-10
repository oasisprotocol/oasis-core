// Package cmd implements the commands for MKVS interoperability test helpers.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common/version"
)

var rootCmd = &cobra.Command{
	Use:     "mkvs-test-helpers",
	Short:   "MKVS interoperability test helpers",
	Version: version.SoftwareVersion,
}

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
