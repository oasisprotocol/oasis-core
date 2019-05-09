// Package staking implements the staking token backend.
package staking

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/staking/memory"
	"github.com/oasislabs/ekiden/go/staking/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgBackend = "staking.backend"

	cfgDebugGenesisState = "staking.debug.genesis_state"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, tmService service.TendermintService) (api.Backend, error) {
	var (
		impl    api.Backend
		err     error
		backend = viper.GetString(cfgBackend)
	)

	// Pull in the debug genesis state if configured.
	var debugGenesisState *api.Genesis
	if m := viper.GetStringMapString(cfgDebugGenesisState); len(m) > 0 {
		if debugGenesisState, err = api.NewGenesis(m); err != nil {
			return nil, err
		}
	}

	switch strings.ToLower(backend) {
	case memory.BackendName:
		impl, err = memory.New(debugGenesisState)
	case tendermint.BackendName:
		impl, err = tendermint.New(ctx, debugGenesisState, tmService)
	default:
		err = fmt.Errorf("staking: unsupported backend: '%v'", backend)
	}

	return impl, err
}

// RegisterFlags registers the configuration flags with the provided command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgBackend, memory.BackendName, "Staking backend")

		// cfgDebugGenesisState isn't for anything but test cases.
		cmd.Flags().StringToString(cfgDebugGenesisState, nil, "(Debug only) Staking genesis state")
		_ = cmd.Flags().MarkHidden(cfgDebugGenesisState)
	}

	for _, v := range []string{
		cfgBackend,
		cfgDebugGenesisState,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
