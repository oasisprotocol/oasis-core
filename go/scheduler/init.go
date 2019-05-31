// Package scheduler implements the scheduler backend.
package scheduler

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/scheduler/trivial"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const cfgBackend = "scheduler.backend"

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, timeSource epochtime.Backend, reg registry.Backend, beacon beacon.Backend, service service.TendermintService) (api.Backend, error) {
	backend := viper.GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case trivial.BackendName:
		return trivial.New(ctx, service)
	default:
		return nil, fmt.Errorf("scheduler: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgBackend, trivial.BackendName, "Scheduler backend")
	}

	for _, v := range []string{
		cfgBackend,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
