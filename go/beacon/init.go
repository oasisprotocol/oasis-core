// Package beacon implements the random beacon backend.
package beacon

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/beacon/insecure"
	"github.com/oasislabs/ekiden/go/beacon/tendermint"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const cfgBackend = "beacon.backend"

// New constructs a new Backend based on the configuration flags.
func New(timeSource epochtime.Backend, tmService service.TendermintService) (api.Backend, error) {
	backend := viper.GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case insecure.BackendName:
		return insecure.New(timeSource), nil
	case tendermint.BackendName:
		return tendermint.New(timeSource, tmService)
	default:
		return nil, fmt.Errorf("beacon: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().String(cfgBackend, insecure.BackendName, "Random beacon backend")

	for _, v := range []string{
		cfgBackend,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
