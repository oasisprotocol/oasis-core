// Package registry implements the entity and runtime registry backend.
package registry

import (
	"context"
	"fmt"
	"strings"

	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/registry/tendermint"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// New constructs a new Backend.
func New(ctx context.Context, timeSource epochtime.Backend, tmService service.TendermintService) (api.Backend, error) {
	// XXX: It looks funny to query the Tendermint service to give us the name
	// of the consensus backend, but this will be fixed once issue #1879 is done.
	backend := tmService.GetGenesis().Consensus.Backend

	var impl api.Backend
	var err error

	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		impl, err = tendermint.New(ctx, timeSource, tmService)
	default:
		return nil, fmt.Errorf("registry: unsupported backend: '%v'", backend)
	}
	if err != nil {
		return nil, err
	}

	return newMetricsWrapper(ctx, impl), nil
}
