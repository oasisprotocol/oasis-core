// Package registry implements the registry sub-commands.
package registry

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/ekiden/cmd/registry/entity"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/registry/runtime"
)

var (
	registryCmd = &cobra.Command{
		Use:   "registry",
		Short: "registry backend utilities",
	}
)

// Register registers the registry sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	entity.Register(registryCmd)
	runtime.Register(registryCmd)

	parentCmd.AddCommand(registryCmd)
}
