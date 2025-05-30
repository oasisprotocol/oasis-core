// Package keymanager provides the CometBFT backed key manager management
// implementation.
package keymanager

import (
	"context"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"

	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	churpAPI "github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	secretsAPI "github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// ServiceClient is the key manager service client.
type ServiceClient struct {
	tmapi.BaseServiceClient

	descriptor *tmapi.ServiceDescriptor

	secretsClient *secrets.ServiceClient
	churpClient   *churp.ServiceClient
}

// New constructs a new CometBFT backed key manager service client.
func New(querier *app.QueryFactory) *ServiceClient {
	descriptor := tmapi.NewServiceDescriptor(api.ModuleName, app.EventType, 1)
	descriptor.AddQuery(app.QueryApp)

	return &ServiceClient{
		descriptor:    descriptor,
		secretsClient: secrets.New(querier),
		churpClient:   churp.New(querier),
	}
}

// StateToGenesis implements api.Backend.
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

// Secrets implements api.Backend.
func (sc *ServiceClient) Secrets() secretsAPI.Backend {
	return sc.secretsClient
}

// Churp implements api.Backend.
func (sc *ServiceClient) Churp() churpAPI.Backend {
	return sc.churpClient
}

// ServiceDescriptor implements api.ServiceClient.
func (sc *ServiceClient) ServiceDescriptor() *tmapi.ServiceDescriptor {
	return sc.descriptor
}

// DeliverEvent implements api.ServiceClient.
func (sc *ServiceClient) DeliverEvent(_ context.Context, _ int64, _ cmttypes.Tx, ev *cmtabcitypes.Event) error {
	if err := sc.secretsClient.DeliverEvent(ev); err != nil {
		return err
	}
	return sc.churpClient.DeliverEvent(ev)
}
