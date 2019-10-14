// Package beacon implements the random beacon backend.
package beacon

import (
	"context"
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/beacon/tendermint"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	commonFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

const (
	// CfgDebugDeterministic is the enable deterministic beacon output flag.
	CfgDebugDeterministic = "beacon.debug.deterministic"
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
		DebugDeterministic: viper.GetBool(CfgDebugDeterministic),
	}
}

func init() {
	Flags.Bool(CfgDebugDeterministic, false, "enable deterministic beacon output (UNSAFE)")

	_ = viper.BindPFlags(Flags)
}
