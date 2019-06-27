// Package beacon implements the random beacon backend.
package beacon

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/beacon/tendermint"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgBackend            = "beacon.backend"
	cfgDebugDeterministic = "beacon.debug.deterministic"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, timeSource epochtime.Backend, tmService service.TendermintService) (api.Backend, error) {
	debugDeterministic := viper.GetBool(cfgDebugDeterministic)

	backend := viper.GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		return tendermint.New(ctx, timeSource, tmService, debugDeterministic)
	default:
		return nil, fmt.Errorf("beacon: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgBackend, tendermint.BackendName, "Random beacon backend")
		cmd.Flags().Bool(cfgDebugDeterministic, false, "enable deterministic beacon output (UNSAFE)")
	}

	for _, v := range []string{
		cfgBackend,
		cfgDebugDeterministic,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
