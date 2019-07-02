// Package registry implements the entity and runtime registry backend.
package registry

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/registry/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgDebugAllowRuntimeRegistration = "registry.debug.allow_runtime_registration"
)

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
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgDebugAllowRuntimeRegistration, false, "enable non-genesis runtime registration (UNSAFE)")
	}

	for _, v := range []string{
		cfgDebugAllowRuntimeRegistration,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
