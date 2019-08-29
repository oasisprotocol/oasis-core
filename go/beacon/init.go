// Package beacon implements the random beacon backend.
package beacon

import (
	"context"
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/beacon/tendermint"
	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgDebugDeterministic = "beacon.debug.deterministic"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, timeSource epochtime.Backend, tmService service.TendermintService) (api.Backend, error) {
	backend := commonFlags.ConsensusBackend()
	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		return tendermint.New(ctx, timeSource, tmService, flagsToConfig())
	default:
		return nil, fmt.Errorf("beacon: unsupported backend: '%v'", backend)
	}
}

func flagsToConfig() *api.Config {
	return &api.Config{
		DebugDeterministic: viper.GetBool(cfgDebugDeterministic),
	}
}

func init() {
	Flags.Bool(cfgDebugDeterministic, false, "enable deterministic beacon output (UNSAFE)")

	_ = viper.BindPFlags(Flags)
}
