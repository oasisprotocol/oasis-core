// Package staking implements the staking token backend.
package staking

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/json"
	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/staking/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgDebugGenesisState = "staking.debug.genesis_state"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, tmService service.TendermintService) (api.Backend, error) {
	var (
		impl    api.Backend
		err     error
		backend = commonFlags.ConsensusBackend()
	)

	// Pull in the debug genesis state if configured.
	var debugGenesisState *api.Genesis
	if strGenesis := viper.GetString(cfgDebugGenesisState); strGenesis != "" {
		var tmp api.Genesis
		if err = json.Unmarshal([]byte(strGenesis), &tmp); err != nil {
			return nil, err
		}
		debugGenesisState = &tmp
	}

	switch strings.ToLower(backend) {
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
		// cfgDebugGenesisState isn't for anything but test cases.
		cmd.Flags().String(cfgDebugGenesisState, "", "(Debug only) Staking genesis state")
		_ = cmd.Flags().MarkHidden(cfgDebugGenesisState)
	}

	for _, v := range []string{
		cfgDebugGenesisState,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
