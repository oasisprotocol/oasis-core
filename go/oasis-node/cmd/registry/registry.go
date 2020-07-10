// Package registry implements the registry sub-commands.
package registry

import (
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/entity"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/node"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/runtime"
)

var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "registry backend utilities",
}

// Register registers the registry sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	entity.Register(registryCmd)
	node.Register(registryCmd)
	runtime.Register(registryCmd)

	parentCmd.AddCommand(registryCmd)
}
