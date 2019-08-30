// Package scheduler implements the scheduler backend.
package scheduler

import (
	"context"
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/scheduler/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const cfgDebugBypassStake = "scheduler.debug.bypass_stake" // nolint: gosec

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, timeSource epochtime.Backend, reg registry.Backend, beacon beacon.Backend, service service.TendermintService) (api.Backend, error) {
	backend := commonFlags.ConsensusBackend()
	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		return tendermint.New(ctx, timeSource, service, flagsToConfig())
	default:
		return nil, fmt.Errorf("scheduler: unsupported backend: '%v'", backend)
	}
}

func flagsToConfig() *api.Config {
	return &api.Config{
		DebugBypassStake: viper.GetBool(cfgDebugBypassStake),
	}
}

func init() {
	Flags.Bool(cfgDebugBypassStake, false, "bypass all stake checks and operations (UNSAFE)")

	_ = viper.BindPFlags(Flags)
}
