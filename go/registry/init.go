// Package registry implements the entity and runtime registry backend.
package registry

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/registry/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	ticker "github.com/oasislabs/ekiden/go/ticker/api"
)

const (
	cfgDebugAllowRuntimeRegistration = "registry.debug.allow_runtime_registration"
	cfgDebugBypassStake              = "registry.debug.bypass_stake" // nolint: gosec
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, timeSource ticker.Backend, tmService service.TendermintService) (api.Backend, error) {
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

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgDebugAllowRuntimeRegistration, false, "enable non-genesis runtime registration (UNSAFE)")
		cmd.Flags().Bool(cfgDebugBypassStake, false, "bypass all stake checks and operations (UNSAFE)")
	}

	for _, v := range []string{
		cfgDebugAllowRuntimeRegistration,
		cfgDebugBypassStake,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
