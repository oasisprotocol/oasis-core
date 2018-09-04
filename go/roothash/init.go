// Package roothash implements the root hash backend.
package roothash

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/memory"
	"github.com/oasislabs/ekiden/go/roothash/tendermint"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgBackend = "roothash.backend"
)

var flagBackend string

// New constructs a new Backend based on the configuration flags.
func New(
	cmd *cobra.Command,
	timeSource epochtime.Backend,
	scheduler scheduler.Backend,
	storage storage.Backend,
	registry registry.Backend,
	tmService service.TendermintService,
) (api.Backend, error) {
	backend, _ := cmd.Flags().GetString(cfgBackend)

	var impl api.Backend
	var err error

	switch strings.ToLower(backend) {
	case memory.BackendName:
		impl = memory.New(scheduler, storage, registry)
	case tendermint.BackendName:
		impl, err = tendermint.New(timeSource, scheduler, storage, tmService)
	default:
		return nil, fmt.Errorf("roothash: unsupported backend: '%v'", backend)
	}
	if err != nil {
		return nil, err
	}

	return newMetricsWrapper(impl), nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagBackend, cfgBackend, memory.BackendName, "Root hash backend")

	for _, v := range []string{
		cfgBackend,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
