// Package epochtime implements the Oasis timekeeping backend.
package epochtime

import (
	"context"
	"fmt"
	"strings"

	"github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/epochtime/tendermint"
	"github.com/oasislabs/oasis-core/go/epochtime/tendermint_mock"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, tmService service.TendermintService) (api.Backend, error) {
	// Fetch config from genesis document.
	params := tmService.GetGenesis().EpochTime.Parameters

	// TODO: Change this to a simple DebugMockBackend bool flag (probably in #1879).
	backend := params.Backend
	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		interval := params.Interval
		return tendermint.New(ctx, tmService, interval)
	case tendermintmock.BackendName:
		return tendermintmock.New(ctx, tmService)
	default:
		return nil, fmt.Errorf("epochtime: unsupported backend: '%v'", backend)
	}
}
