// Package roothash implements the root hash backend.
package roothash

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/memory"
	"github.com/oasislabs/ekiden/go/roothash/tendermint"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgBackend      = "roothash.backend"
	cfgRoundTimeout = "roothash.round_timeout"
)

// New constructs a new Backend based on the configuration flags.
func New(
	ctx context.Context,
	timeSource epochtime.Backend,
	scheduler scheduler.Backend,
	registry registry.Backend,
	beacon beacon.Backend,
	tmService service.TendermintService,
) (api.Backend, error) {
	backend := viper.GetString(cfgBackend)

	roundTimeout := viper.GetDuration(cfgRoundTimeout)

	var impl api.Backend
	var err error

	switch strings.ToLower(backend) {
	case memory.BackendName:
		impl = memory.New(ctx, scheduler, registry, nil, roundTimeout)
	case tendermint.BackendName:
		impl, err = tendermint.New(ctx, timeSource, scheduler, beacon, tmService, roundTimeout)
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
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgBackend, memory.BackendName, "Root hash backend")
		cmd.Flags().Duration(cfgRoundTimeout, 10*time.Second, "Root hash round timeout")
	}

	for _, v := range []string{
		cfgBackend,
		cfgRoundTimeout,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
