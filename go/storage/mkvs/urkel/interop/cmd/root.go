// Package cmd implements the commands for Urkel interoperability test helpers.
package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:     "urkel-test-helpers",
		Short:   "Urkel interoperability test helpers",
		Version: "0.2.0-alpha",
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
