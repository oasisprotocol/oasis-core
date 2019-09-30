// Package staking implements the staking token backend.
package staking

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/staking/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgDebugGenesisState = "staking.debug.genesis_state"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

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

func init() {
	// cfgDebugGenesisState isn't for anything but test cases.
	Flags.String(cfgDebugGenesisState, "", "(Debug only) Staking genesis state")
	_ = Flags.MarkHidden(cfgDebugGenesisState)

	_ = viper.BindPFlags(Flags)
}
