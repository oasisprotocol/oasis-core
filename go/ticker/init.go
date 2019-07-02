// Package ticker implements the Oasis timekeeping backend.
package ticker

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	"github.com/oasislabs/ekiden/go/ticker/api"
	"github.com/oasislabs/ekiden/go/ticker/tendermint"
	tendermintMock "github.com/oasislabs/ekiden/go/ticker/tendermint_mock"
)

const (
	cfgTickerDebugSettable = "ticker.debug.settable"
	cfgTickerInterval      = "ticker.interval"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, tmService service.TendermintService) (api.Backend, error) {
	backend := commonFlags.ConsensusBackend()
	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		settable := viper.GetBool(cfgTickerDebugSettable)
		tickInterval := viper.GetInt64(cfgTickerInterval)
		if settable {
			return tendermintMock.New(ctx, tmService)
		}
		return tendermint.New(ctx, tmService, tickInterval)
	default:
		return nil, fmt.Errorf("ticker: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgTickerDebugSettable, false, "enable settable ticker (should be used for DEBUG purposes only)")
		cmd.Flags().Int64(cfgTickerInterval, 8640, "Tick interval (in blocks)")
	}

	for _, v := range []string{
		cfgTickerDebugSettable,
		cfgTickerInterval,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
