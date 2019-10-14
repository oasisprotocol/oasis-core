// Package keymanager implements the key manager backend.
package keymanager

import (
	"context"
	"fmt"
	"strings"

	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
	"github.com/oasislabs/oasis-core/go/keymanager/tendermint"
	commonFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// New constructs a new Backend based on the configuration flags.
func New(
	ctx context.Context,
	timeSource epochtime.Backend,
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
