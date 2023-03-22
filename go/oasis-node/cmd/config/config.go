// Package config implements various configuration-related sub-commands.
package config

import (
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/config/migrate"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "config utilities",
}

// Register registers the config sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	migrate.Register(configCmd)

	parentCmd.AddCommand(configCmd)
}
