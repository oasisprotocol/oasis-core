// Package keymanager implements the key manager backend.
package keymanager

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	"github.com/oasislabs/ekiden/go/keymanager/tendermint"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const cfgBackend = "keymanager.backend"

// New constructs a new Backend based on the configuration flags.
func New(
	ctx context.Context,
	timeSource epochtime.Backend,
	registry registry.Backend,
	service service.TendermintService,
) (api.Backend, error) {
	backend := viper.GetString(cfgBackend)

	var (
		impl api.Backend
		err  error
	)

	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		impl, err = tendermint.New(ctx, timeSource, service)
	default:
		return nil, fmt.Errorf("keymanager: unsupported backend: '%v'", backend)
	}

	return impl, err
}

// RegisterFlags registers the configuration flags with the provided command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgBackend, tendermint.BackendName, "Key manager backend")
	}

	for _, v := range []string{
		cfgBackend,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
