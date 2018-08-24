// Package registry implements the entity and contract registry backend.
package registry

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/registry/memory"
	"github.com/oasislabs/ekiden/go/registry/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const cfgBackend = "registry.backend"

var flagBackend string

// New constructs a new Backend based on the configuration flags.
func New(cmd *cobra.Command, timeSource epochtime.Backend, tmService service.TendermintService) (api.Backend, error) {
	backend, _ := cmd.Flags().GetString(cfgBackend)

	var impl api.Backend
	var err error

	switch strings.ToLower(backend) {
	case memory.BackendName:
		impl = memory.New(timeSource)
	case tendermint.BackendName:
		impl, err = tendermint.New(timeSource, tmService)
	default:
		return nil, fmt.Errorf("registry: unsupported backend: '%v'", backend)
	}
	if err != nil {
		return nil, err
	}

	return newMetricsWrapper(impl), nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagBackend, cfgBackend, memory.BackendName, "Registry backend")

	for _, v := range []string{
		cfgBackend,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
