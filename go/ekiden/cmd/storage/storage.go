// Package storage implements various storage related sub-commands.
package storage

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/ekiden/cmd/storage/benchmark"
)

var storageCmd = &cobra.Command{
	Use:   "storage",
	Short: "storage services and utilities",
}

// Register registers the storage sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	benchmark.Register(storageCmd)

	parentCmd.AddCommand(storageCmd)
}
