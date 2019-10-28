// Package staking implements the staking token backend.
package staking

import (
	"context"
	"fmt"
	"strings"

	"github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/staking/tendermint"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, tmService service.TendermintService) (api.Backend, error) {
	// XXX: It looks funny to query the Tendermint service to give us the name
	// of the consensus backend, but this will be fixed once issue #1879 is done.
	var (
		impl    api.Backend
		err     error
		backend = tmService.GetGenesis().Consensus.Backend
	)

	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		impl, err = tendermint.New(ctx, tmService)
	default:
		err = fmt.Errorf("staking: unsupported backend: '%v'", backend)
	}

	return impl, err
}
