// Package governance implements the tendermint backed governance backend.
package governance

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance"
	"github.com/oasisprotocol/oasis-core/go/governance/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// ServiceClient is the registry service client interface.
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

func (sc *serviceClient) ActiveProposals(ctx context.Context, height int64) ([]*api.Proposal, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ActiveProposals(ctx)
}

func (sc *serviceClient) Proposals(ctx context.Context, height int64) ([]*api.Proposal, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Proposals(ctx)
}

func (sc *serviceClient) Proposal(ctx context.Context, query *api.ProposalQuery) (*api.Proposal, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Proposal(ctx, query.ProposalID)
}

func (sc *serviceClient) Votes(ctx context.Context, query *api.ProposalQuery) ([]*api.VoteEntry, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Votes(ctx, query.ProposalID)
}

func (sc *serviceClient) PendingUpgrades(ctx context.Context, height int64) ([]*upgrade.Descriptor, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.PendingUpgrades(ctx)
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
	var results *tmrpctypes.ResultBlockResults
	results, err := sc.backend.GetBlockResults(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get tendermint block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Get transactions at given height.
	txns, err := sc.backend.GetTransactions(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get tendermint transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	var events []*api.Event
	// Decode events from block results.
	blockEvs, err := EventsFromTendermint(nil, results.Height, results.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	blockEvs, err = EventsFromTendermint(nil, results.Height, results.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.
		evs, txErr := EventsFromTendermint(txns[txIdx], results.Height, txResult.Events)
		if txErr != nil {
			return nil, txErr
		}
		events = append(events, evs...)
	}

	return events, nil
}

func (sc *serviceClient) WatchEvents(ctx context.Context) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
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
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []tmpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, tx tmtypes.Tx, ev *tmabcitypes.Event) error {
	events, err := EventsFromTendermint(tx, height, []tmabcitypes.Event{*ev})
	if err != nil {
		return fmt.Errorf("governance: failed to process tendermint events: %w", err)
	}

	// Notify subscribers of events.
	for _, ev := range events {
		sc.eventNotifier.Broadcast(ev)
	}

	return nil
}

// EventsFromTendermint extracts governance events from tendermint events.
func EventsFromTendermint(
	tx tmtypes.Tx,
	height int64,
	tmEvents []tmabcitypes.Event,
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
		// Ignore events that don't relate to the governance app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case eventsAPI.IsAttributeKind(key, &api.ProposalSubmittedEvent{}):
				// Proposal submitted event.
				var e api.ProposalSubmittedEvent
				if err := eventsAPI.DecodeValue(string(val), &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("governance: corrupt ProposalSubmitted event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, ProposalSubmitted: &e}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.ProposalExecutedEvent{}):
				//  Proposal executed event.
				var e api.ProposalExecutedEvent
				if err := eventsAPI.DecodeValue(string(val), &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("governance: corrupt ProposalExecuted event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, ProposalExecuted: &e}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.ProposalFinalizedEvent{}):
				// Proposal finalized event.
				var e api.ProposalFinalizedEvent
				if err := eventsAPI.DecodeValue(string(val), &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("governance: corrupt ProposalFinalized event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, ProposalFinalized: &e}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.VoteEvent{}):
				// Vote event.
				var e api.VoteEvent
				if err := eventsAPI.DecodeValue(string(val), &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("governance: corrupt Vote event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Vote: &e}
				events = append(events, evt)
			default:
				errs = multierror.Append(errs, fmt.Errorf("governance: unknown event type: key: %s, val: %s", key, val))
			}
		}
	}

	return events, errs
}

// New constructs a new tendermint backed governance Backend instance.
func New(ctx context.Context, backend tmapi.Backend) (ServiceClient, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, err
	}

	return &serviceClient{
		logger:        logging.GetLogger("staking/tendermint"),
		backend:       backend,
		querier:       a.QueryFactory().(*app.QueryFactory),
		eventNotifier: pubsub.NewBroker(false),
	}, nil
}
