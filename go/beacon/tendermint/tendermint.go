// Package tendermint implements the tendermint backed beacon backend.
package tendermint

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/beacon"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = tmapi.BackendName

var _ api.Backend = (*Backend)(nil)

// Backend is a tendermint backed random beacon.
type Backend struct {
	logger *logging.Logger

	service service.TendermintService
}

func (t *Backend) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	resp, err := t.service.Query(app.QueryGetBeacon, nil, height)
	if err != nil {
		return nil, errors.Wrap(err, "beacon: failed to query beacon")
	}

	return resp, nil
}

// New constructs a new tendermint backed beacon Backend instance.
func New(ctx context.Context, timeSource epochtime.Backend, service service.TendermintService, cfg *api.Config) (api.Backend, error) {
	if err := service.ForceInitialize(); err != nil {
		return nil, err
	}

	// Initialize and register the tendermint service component.
	app := app.New(timeSource, cfg)
	if err := service.RegisterApplication(app, nil); err != nil {
		return nil, err
	}

	t := &Backend{
		logger:  logging.GetLogger("beacon/tendermint"),
		service: service,
	}

	return t, nil
}
