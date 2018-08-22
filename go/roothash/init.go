// Package roothash implements the root hash backend.
package roothash

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/memory"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

const (
	cfgBackend = "roothash.backend"

	backendMemory = "memory"
)

var flagBackend string

// New constructs a new Backend based on the configuration flags.
func New(cmd *cobra.Command, scheduler scheduler.Backend, storage storage.Backend, registry registry.Backend) (api.Backend, error) {
	backend, _ := cmd.Flags().GetString(cfgBackend)

	var impl api.Backend

	switch strings.ToLower(backend) {
	case backendMemory:
		impl = memory.New(scheduler, storage, registry)
	default:
		return nil, fmt.Errorf("roothash: unsupported backend: '%v'", backend)
	}

	return newMetricsWrapper(impl), nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagBackend, cfgBackend, backendMemory, "Root hash backend")

	for _, v := range []string{
		cfgBackend,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
