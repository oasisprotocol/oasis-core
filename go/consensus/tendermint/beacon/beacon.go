// Package beacon implements the tendermint backed beacon backend.
package beacon

import (
	"context"

	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"

	"github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/service"
)

// ServiceClient is the beacon service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	querier *app.QueryFactory
}

func (sc *serviceClient) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Beacon(ctx)
}

func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []tmpubsub.Query{app.QueryApp})
}

// New constructs a new tendermint backed beacon Backend instance.
func New(ctx context.Context, service service.TendermintService) (ServiceClient, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	sc := &serviceClient{
		logger:  logging.GetLogger("beacon/tendermint"),
		querier: a.QueryFactory().(*app.QueryFactory),
	}

	return sc, nil
}
