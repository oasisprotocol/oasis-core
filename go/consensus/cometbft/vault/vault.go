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
	"github.com/oasisprotocol/oasis-core/go/vault/api"
)

// ServiceClient is the vault service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	backend tmapi.Backend
	querier *app.QueryFactory

	eventNotifier *pubsub.Broker
}

func (sc *serviceClient) Vaults(ctx context.Context, height int64) ([]*api.Vault, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Vaults(ctx)
}

func (sc *serviceClient) Vault(ctx context.Context, query *api.VaultQuery) (*api.Vault, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Vault(ctx, query.Address)
}

func (sc *serviceClient) AddressState(ctx context.Context, query *api.AddressQuery) (*api.AddressState, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.AddressState(ctx, query.Vault, query.Address)
}

func (sc *serviceClient) PendingActions(ctx context.Context, query *api.VaultQuery) ([]*api.PendingAction, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.PendingActions(ctx, query.Address)
}

func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *serviceClient) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
	// Get block results at given height.
	var results *cmtrpctypes.ResultBlockResults
	results, err := sc.backend.GetBlockResults(ctx, height)
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

	var events []*api.Event
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

func (sc *serviceClient) WatchEvents(context.Context) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.Event)
	sub := sc.eventNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}

func (sc *serviceClient) Cleanup() {
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []cmtpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(_ context.Context, height int64, tx cmttypes.Tx, ev *cmtabcitypes.Event) error {
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
) ([]*api.Event, error) {
	var txHash hash.Hash
	switch tx {
	case nil:
		txHash.Empty()
	default:
		txHash = hash.NewFromBytes(tx)
	}

	var events []*api.Event
	var errs error
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the vault app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			evt := &api.Event{Height: height, TxHash: txHash}
			switch {
			case eventsAPI.IsAttributeKind(key, &api.ActionSubmittedEvent{}):
				// Action submitted event.
				var e api.ActionSubmittedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionSubmitted event: %w", err))
					continue
				}

				evt.ActionSubmitted = &e
			case eventsAPI.IsAttributeKind(key, &api.ActionCanceledEvent{}):
				// Action canceled event.
				var e api.ActionCanceledEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionCanceled event: %w", err))
					continue
				}

				evt.ActionCanceled = &e
			case eventsAPI.IsAttributeKind(key, &api.ActionExecutedEvent{}):
				// Action executed event.
				var e api.ActionExecutedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionExecuted event: %w", err))
					continue
				}

				evt.ActionExecuted = &e
			case eventsAPI.IsAttributeKind(key, &api.StateChangedEvent{}):
				// State changed event.
				var e api.StateChangedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt StateChanged event: %w", err))
					continue
				}

				evt.StateChanged = &e
			case eventsAPI.IsAttributeKind(key, &api.PolicyUpdatedEvent{}):
				// Policy updated event.
				var e api.PolicyUpdatedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt PolicyUpdated event: %w", err))
					continue
				}

				evt.PolicyUpdated = &e
			case eventsAPI.IsAttributeKind(key, &api.AuthorityUpdatedEvent{}):
				// Action submitted event.
				var e api.AuthorityUpdatedEvent
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

// New constructs a new CometBFT backed vault Backend instance.
func New(backend tmapi.Backend) (ServiceClient, error) {
	// Initialize and register the CometBFT service component.
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, err
	}

	return &serviceClient{
		logger:        logging.GetLogger("cometbft/vault"),
		backend:       backend,
		querier:       a.QueryFactory().(*app.QueryFactory),
		eventNotifier: pubsub.NewBroker(false),
	}, nil
}
