// Package registry implements the entity and runtime registry backend.
package registry

import (
	"context"
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	commonFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/registry/tendermint"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

const (
	cfgDebugAllowRuntimeRegistration = "registry.debug.allow_runtime_registration"
	cfgDebugBypassStake              = "registry.debug.bypass_stake" // nolint: gosec
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, timeSource epochtime.Backend, tmService service.TendermintService) (api.Backend, error) {
	backend := commonFlags.ConsensusBackend()

	var impl api.Backend
	var err error

	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		impl, err = tendermint.New(ctx, timeSource, tmService, flagsToConfig())
	default:
		return nil, fmt.Errorf("registry: unsupported backend: '%v'", backend)
	}
	if err != nil {
		return nil, err
	}

	return newMetricsWrapper(ctx, impl), nil
}

func flagsToConfig() *api.Config {
	return &api.Config{
		DebugAllowRuntimeRegistration: viper.GetBool(cfgDebugAllowRuntimeRegistration),
		DebugBypassStake:              viper.GetBool(cfgDebugBypassStake),
	}
}

func init() {
	Flags.Bool(cfgDebugAllowRuntimeRegistration, false, "enable non-genesis runtime registration (UNSAFE)")
	Flags.Bool(cfgDebugBypassStake, false, "bypass all stake checks and operations (UNSAFE)")

	_ = viper.BindPFlags(Flags)
}
