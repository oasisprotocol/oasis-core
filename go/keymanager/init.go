// Package keymanager implements the key manager backend.
package keymanager

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	"github.com/oasislabs/ekiden/go/keymanager/tendermint"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	ticker "github.com/oasislabs/ekiden/go/ticker/api"
)

// New constructs a new Backend based on the configuration flags.
func New(
	ctx context.Context,
	timeSource ticker.Backend,
	registry registry.Backend,
	service service.TendermintService,
) (api.Backend, error) {
	backend := commonFlags.ConsensusBackend()

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
}
