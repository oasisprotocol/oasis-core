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
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	churpAPI "github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	secretsAPI "github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// ServiceClient is the registry service client.
type ServiceClient struct {
	tmapi.BaseServiceClient

	secretsClient *secrets.ServiceClient
	churpClient   *churp.ServiceClient
}

// Implements api.Backend.
func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	secretsGenesis, err := sc.secretsClient.StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	churpGenesis, err := sc.churpClient.StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	return &api.Genesis{
		Genesis: *secretsGenesis,
		Churp:   churpGenesis,
	}, nil
}

// Implements api.Backend.
func (sc *ServiceClient) Secrets() secretsAPI.Backend {
	return sc.secretsClient
}

// Implements api.Backend.
func (sc *ServiceClient) Churp() churpAPI.Backend {
	return sc.churpClient
}

// Implements api.ServiceClient.
func (sc *ServiceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []cmtpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *ServiceClient) DeliverEvent(_ context.Context, _ int64, _ cmttypes.Tx, ev *cmtabcitypes.Event) error {
	if err := sc.secretsClient.DeliverEvent(ev); err != nil {
		return err
	}
	return sc.churpClient.DeliverEvent(ev)
}

// New constructs a new CometBFT backed key manager management Backend
// instance.
func New(ctx context.Context, querier *app.QueryFactory) (*ServiceClient, error) {
	secretsClient, err := secrets.New(ctx, querier)
	if err != nil {
		return nil, fmt.Errorf("cometbft/keymanager: failed to create secrets client: %w", err)
	}

	churpClient, err := churp.New(ctx, querier)
	if err != nil {
		return nil, fmt.Errorf("cometbft/keymanager: failed to create churp client: %w", err)
	}

	sc := ServiceClient{
		secretsClient: secretsClient,
		churpClient:   churpClient,
	}

	return &sc, nil
}
