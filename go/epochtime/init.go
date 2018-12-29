// Package epochtime implements the Oasis timekeeping backend.
package epochtime

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/epochtime/system"
	"github.com/oasislabs/ekiden/go/epochtime/tendermint"
	"github.com/oasislabs/ekiden/go/epochtime/tendermint_mock"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgBackend            = "epochtime.backend"
	cfgSystemInterval     = "epochtime.system.interval"
	cfgTendermintInterval = "epochtime.tendermint.interval"
)

// New constructs a new Backend based on the configuration flags.
func New(tmService service.TendermintService) (api.Backend, error) {
	backend := viper.GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case system.BackendName:
		interval := viper.GetInt64(cfgSystemInterval)
		return system.New(interval)
	case mock.BackendName:
		return mock.New(), nil
	case tendermint.BackendName:
		interval := viper.GetInt64(cfgTendermintInterval)
		return tendermint.New(tmService, interval)
	case tendermintmock.BackendName:
		return tendermintmock.New(tmService)
	default:
		return nil, fmt.Errorf("epochtime: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().String(cfgBackend, system.BackendName, "Epoch time backend")
	cmd.Flags().Int64(cfgSystemInterval, api.EpochInterval, "Epoch interval")
	cmd.Flags().Int64(cfgTendermintInterval, api.EpochInterval, "Epoch interval (in blocks)")

	for _, v := range []string{
		cfgBackend,
		cfgSystemInterval,
		cfgTendermintInterval,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
