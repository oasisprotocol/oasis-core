// Package tendermint implements the tendermint backed beacon backend.
package tendermint

import (
	"context"

	"github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/logging"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	tmapi "github.com/oasislabs/oasis-core/go/tendermint/api"
	app "github.com/oasislabs/oasis-core/go/tendermint/apps/beacon"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = tmapi.BackendName

var _ api.Backend = (*tendermintBackend)(nil)

type tendermintBackend struct {
	logger *logging.Logger

	service service.TendermintService
	querier *app.QueryFactory
}

func (t *tendermintBackend) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	q, err := t.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Beacon(ctx)
}

func (t *tendermintBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := t.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

// New constructs a new tendermint backed beacon Backend instance.
func New(ctx context.Context, timeSource epochtime.Backend, service service.TendermintService) (api.Backend, error) {
	if err := service.ForceInitialize(); err != nil {
		return nil, err
	}

	// Fetch config from genesis document.
	cfg := service.GetGenesis().Beacon

	// Initialize and register the tendermint service component.
	a := app.New(timeSource, &cfg)
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	t := &tendermintBackend{
		logger:  logging.GetLogger("beacon/tendermint"),
		service: service,
		querier: a.QueryFactory().(*app.QueryFactory),
	}

	return t, nil
}
