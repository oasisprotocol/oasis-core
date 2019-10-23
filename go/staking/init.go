// Package staking implements the staking token backend.
package staking

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/staking/tendermint"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

const (
	cfgDebugGenesisState = "staking.debug.genesis_state"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, timeSource epochtime.Backend, tmService service.TendermintService) (api.Backend, error) {
	// XXX: It looks funny to query the Tendermint service to give us the name
	// of the consensus backend, but this will be fixed once issue #1879 is done.
	var (
		impl    api.Backend
		err     error
		backend = tmService.GetGenesis().Consensus.Backend
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
		impl, err = tendermint.New(ctx, timeSource, debugGenesisState, tmService)
	default:
		err = fmt.Errorf("staking: unsupported backend: '%v'", backend)
	}

	return impl, err
}

func init() {
	// cfgDebugGenesisState isn't for anything but test cases.
	Flags.String(cfgDebugGenesisState, "", "(Debug only) Staking genesis state")
	_ = Flags.MarkHidden(cfgDebugGenesisState)

	_ = viper.BindPFlags(Flags)
}
