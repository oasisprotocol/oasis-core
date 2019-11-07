// Package beacon implements the random beacon backend.
package beacon

import (
	"context"
	"fmt"
	"strings"

	"github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/beacon/tendermint"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, tmService service.TendermintService) (api.Backend, error) {
	// XXX: It looks funny to query the Tendermint service to give us the name
	// of the consensus backend, but this will be fixed once issue #1879 is done.
	backend := tmService.GetGenesis().Consensus.Backend
	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		return tendermint.New(ctx, tmService)
	default:
		return nil, fmt.Errorf("beacon: unsupported backend: '%v'", backend)
	}
}
