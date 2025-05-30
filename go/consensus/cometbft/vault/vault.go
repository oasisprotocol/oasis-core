// Package vault implements the CometBFT backed vault backend.
package vault

import (
	"context"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// ServiceClient is the vault service client.
type ServiceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	consensus consensus.Backend
	querier   *app.QueryFactory

	eventNotifier *pubsub.Broker
}

// New constructs a new CometBFT backed vault service client.
func New(consensus consensus.Backend, querier *app.QueryFactory) *ServiceClient {
	return &ServiceClient{
		logger:        logging.GetLogger("cometbft/vault"),
		consensus:     consensus,
		querier:       querier,
		eventNotifier: pubsub.NewBroker(false),
	}
}

func (sc *ServiceClient) Vaults(ctx context.Context, height int64) ([]*vault.Vault, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Vaults(ctx)
}

func (sc *ServiceClient) Vault(ctx context.Context, query *vault.VaultQuery) (*vault.Vault, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Vault(ctx, query.Address)
}

func (sc *ServiceClient) AddressState(ctx context.Context, query *vault.AddressQuery) (*vault.AddressState, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.AddressState(ctx, query.Vault, query.Address)
}

func (sc *ServiceClient) PendingActions(ctx context.Context, query *vault.VaultQuery) ([]*vault.PendingAction, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.PendingActions(ctx, query.Address)
}

func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*vault.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *ServiceClient) GetEvents(ctx context.Context, height int64) ([]*vault.Event, error) {
	// Get block results at given height.
	results, err := tmapi.GetBlockResults(ctx, height, sc.consensus)
	if err != nil {
		sc.logger.Error("failed to get block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Get transactions at given height.
	txns, err := sc.consensus.GetTransactions(ctx, results.Height)
	if err != nil {
		sc.logger.Error("failed to get cometbft transactions",
			"err", err,
			"height", results.Height,
		)
		return nil, err
	}

	var events []*vault.Event
	// Decode events from block results (at the beginning of the block).
	blockEvs, err := EventsFromCometBFT(nil, results.Height, results.Meta.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.Meta.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.
		evs, txErr := EventsFromCometBFT(txns[txIdx], results.Height, txResult.Events)
		if txErr != nil {
			return nil, txErr
		}
		events = append(events, evs...)
	}

	// Decode events from block results (at the end of the block).
	blockEvs, err = EventsFromCometBFT(nil, results.Height, results.Meta.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	return events, nil
}

func (sc *ServiceClient) WatchEvents(context.Context) (<-chan *vault.Event, pubsub.ClosableSubscription, error) {
	ch := make(chan *vault.Event)
	sub := sc.eventNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) ConsensusParameters(ctx context.Context, height int64) (*vault.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}

// ServiceDescriptor implements api.ServiceClient.
func (sc *ServiceClient) ServiceDescriptor() *tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(vault.ModuleName, app.EventType, []cmtpubsub.Query{app.QueryApp})
}

// DeliverEvent implements api.ServiceClient.
func (sc *ServiceClient) DeliverEvent(_ context.Context, height int64, tx cmttypes.Tx, ev *cmtabcitypes.Event) error {
	events, err := EventsFromCometBFT(tx, height, []cmtabcitypes.Event{*ev})
	if err != nil {
		return fmt.Errorf("vault: failed to process cometbft events: %w", err)
	}

	// Notify subscribers of events.
	for _, ev := range events {
		sc.eventNotifier.Broadcast(ev)
	}

	return nil
}
