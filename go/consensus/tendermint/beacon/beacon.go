// Package beacon implements the tendermint backed beacon backend.
package beacon

import (
	"context"

	"github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/logging"
	tmapi "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/beacon"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
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
func New(ctx context.Context, service service.TendermintService) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
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
