// Package vault implements the CometBFT backed vault backend.
package vault

import (
	"context"
	"errors"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmtrpctypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// ServiceClient is the vault service client.
type ServiceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	backend tmapi.Backend
	querier *app.QueryFactory

	eventNotifier *pubsub.Broker
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
	var results *cmtrpctypes.ResultBlockResults
	results, err := sc.backend.GetCometBFTBlockResults(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get cometbft block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Get transactions at given height.
	txns, err := sc.backend.GetTransactions(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get cometbft transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	var events []*vault.Event
	// Decode events from block results (at the beginning of the block).
	blockEvs, err := EventsFromCometBFT(nil, results.Height, results.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.TxsResults {
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
	blockEvs, err = EventsFromCometBFT(nil, results.Height, results.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	return events, nil
}

func (sc *ServiceClient) WatchEvents(context.Context) (<-chan *vault.Event, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *vault.Event)
	sub := sc.eventNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *ServiceClient) ConsensusParameters(ctx context.Context, height int64) (*vault.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}

func (sc *ServiceClient) Cleanup() {
}

// ServiceDescriptor implements api.ServiceClient.
func (sc *ServiceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
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

// EventsFromCometBFT extracts vault events from CometBFT events.
func EventsFromCometBFT(
	tx cmttypes.Tx,
	height int64,
	tmEvents []cmtabcitypes.Event,
) ([]*vault.Event, error) {
	var txHash hash.Hash
	switch tx {
	case nil:
		txHash.Empty()
	default:
		txHash = hash.NewFromBytes(tx)
	}

	var events []*vault.Event
	var errs error
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the vault app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			evt := &vault.Event{Height: height, TxHash: txHash}
			switch {
			case eventsAPI.IsAttributeKind(key, &vault.ActionSubmittedEvent{}):
				// Action submitted event.
				var e vault.ActionSubmittedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionSubmitted event: %w", err))
					continue
				}

				evt.ActionSubmitted = &e
			case eventsAPI.IsAttributeKind(key, &vault.ActionCanceledEvent{}):
				// Action canceled event.
				var e vault.ActionCanceledEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionCanceled event: %w", err))
					continue
				}

				evt.ActionCanceled = &e
			case eventsAPI.IsAttributeKind(key, &vault.ActionExecutedEvent{}):
				// Action executed event.
				var e vault.ActionExecutedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionExecuted event: %w", err))
					continue
				}

				evt.ActionExecuted = &e
			case eventsAPI.IsAttributeKind(key, &vault.StateChangedEvent{}):
				// State changed event.
				var e vault.StateChangedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt StateChanged event: %w", err))
					continue
				}

				evt.StateChanged = &e
			case eventsAPI.IsAttributeKind(key, &vault.PolicyUpdatedEvent{}):
				// Policy updated event.
				var e vault.PolicyUpdatedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt PolicyUpdated event: %w", err))
					continue
				}

				evt.PolicyUpdated = &e
			case eventsAPI.IsAttributeKind(key, &vault.AuthorityUpdatedEvent{}):
				// Action submitted event.
				var e vault.AuthorityUpdatedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt AuthorityUpdated event: %w", err))
					continue
				}

				evt.AuthorityUpdated = &e
			default:
				errs = errors.Join(errs, fmt.Errorf("vault: unknown event type: key: %s, val: %s", key, val))
				continue
			}

			events = append(events, evt)
		}
	}

	return events, errs
}

// New constructs a new CometBFT backed vault backend instance.
func New(backend tmapi.Backend, querier *app.QueryFactory) *ServiceClient {
	return &ServiceClient{
		logger:        logging.GetLogger("cometbft/vault"),
		backend:       backend,
		querier:       querier,
		eventNotifier: pubsub.NewBroker(false),
	}
}
