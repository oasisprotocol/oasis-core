// Package keymanager provides the CometBFT backed key manager management
// implementation.
package keymanager

import (
	"context"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmttypes "github.com/cometbft/cometbft/types"

	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	secretsAPI "github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// ServiceClient is the registry service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient

	secretsClient *secrets.ServiceClient
}

// Implements api.Backend.
func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	secretsGenesis, err := sc.secretsClient.StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	return secretsGenesis, nil
}

// Implements api.Backend.
func (sc *serviceClient) Secrets() secretsAPI.Backend {
	return sc.secretsClient
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []cmtpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(_ context.Context, _ int64, _ cmttypes.Tx, ev *cmtabcitypes.Event) error {
	return sc.secretsClient.DeliverEvent(ev)
}

// New constructs a new CometBFT backed key manager management Backend
// instance.
func New(ctx context.Context, backend tmapi.Backend) (ServiceClient, error) {
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, fmt.Errorf("cometbft/keymanager: failed to register app: %w", err)
	}

	querier := a.QueryFactory().(*app.QueryFactory)
	secretsClient, err := secrets.New(ctx, querier)
	if err != nil {
		return nil, fmt.Errorf("cometbft/keymanager: failed to create secrets client: %w", err)
	}

	sc := serviceClient{
		secretsClient: secretsClient,
	}

	return &sc, nil
}
