// Package epochtime implements the Oasis timekeeping backend.
package epochtime

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/epochtime/tendermint"
	"github.com/oasislabs/ekiden/go/epochtime/tendermint_mock"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgBackend            = "epochtime.backend"
	cfgTendermintInterval = "epochtime.tendermint.interval"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, tmService service.TendermintService) (api.Backend, error) {
	backend := viper.GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		interval := viper.GetInt64(cfgTendermintInterval)
		return tendermint.New(ctx, tmService, interval)
	case tendermintmock.BackendName:
		return tendermintmock.New(ctx, tmService)
	default:
		return nil, fmt.Errorf("epochtime: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgBackend, tendermint.BackendName, "Epoch time backend")
		cmd.Flags().Int64(cfgTendermintInterval, 86400, "Epoch interval (in blocks)")
	}

	for _, v := range []string{
		cfgBackend,
		cfgTendermintInterval,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
