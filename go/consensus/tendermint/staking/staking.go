// Package staking implements the tendermint backed staking token backend.
package staking

import (
	"bytes"
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/service"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

var _ api.Backend = (*tendermintBackend)(nil)

type tendermintBackend struct {
	logger *logging.Logger

	service service.TendermintService
	querier *app.QueryFactory

	transferNotifier *pubsub.Broker
	burnNotifier     *pubsub.Broker
	escrowNotifier   *pubsub.Broker
	eventNotifier    *pubsub.Broker

	closedCh chan struct{}
}

func (tb *tendermintBackend) TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.TotalSupply(ctx)
}

func (tb *tendermintBackend) CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.CommonPool(ctx)
}

func (tb *tendermintBackend) LastBlockFees(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.LastBlockFees(ctx)
}

func (tb *tendermintBackend) Threshold(ctx context.Context, query *api.ThresholdQuery) (*quantity.Quantity, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Threshold(ctx, query.Kind)
}

func (tb *tendermintBackend) Addresses(ctx context.Context, height int64) ([]api.Address, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Addresses(ctx)
}

func (tb *tendermintBackend) Account(ctx context.Context, query *api.OwnerQuery) (*api.Account, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Account(ctx, query.Owner)
}

func (tb *tendermintBackend) Delegations(ctx context.Context, query *api.OwnerQuery) (map[api.Address]*api.Delegation, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Delegations(ctx, query.Owner)
}

func (tb *tendermintBackend) DebondingDelegations(ctx context.Context, query *api.OwnerQuery) (map[api.Address][]*api.DebondingDelegation, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.DebondingDelegations(ctx, query.Owner)
}

func (tb *tendermintBackend) WatchTransfers(ctx context.Context) (<-chan *api.TransferEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.TransferEvent)
	sub := tb.transferNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) WatchBurns(ctx context.Context) (<-chan *api.BurnEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.BurnEvent)
	sub := tb.burnNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) WatchEscrows(ctx context.Context) (<-chan *api.EscrowEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.EscrowEvent)
	sub := tb.escrowNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (tb *tendermintBackend) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
	// Get block results at given height.
	var results *tmrpctypes.ResultBlockResults
	results, err := tb.service.GetBlockResults(height)
	if err != nil {
		tb.logger.Error("failed to get tendermint block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Get transactions at given height.
	txns, err := tb.service.GetTransactions(ctx, height)
	if err != nil {
		tb.logger.Error("failed to get tendermint transactions",
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

func (tb *tendermintBackend) WatchEvents(ctx context.Context) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.Event)
	sub := tb.eventNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}
func (tb *tendermintBackend) Cleanup() {
	<-tb.closedCh
}

func (tb *tendermintBackend) worker(ctx context.Context) {
	defer close(tb.closedCh)

	sub, err := tb.service.Subscribe("staking-worker", app.QueryApp)
	if err != nil {
		tb.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer tb.service.Unsubscribe("staking-worker", app.QueryApp) // nolint: errcheck

	for {
		var event interface{}

		select {
		case msg := <-sub.Out():
			event = msg.Data()
		case <-sub.Cancelled():
			tb.logger.Debug("worker: terminating, subscription closed")
			return
		case <-ctx.Done():
			return
		}

		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			tb.onEventDataNewBlock(ctx, ev)
		case tmtypes.EventDataTx:
			tb.onEventDataTx(ctx, ev)
		default:
		}
	}
}

func (tb *tendermintBackend) onEventDataNewBlock(ctx context.Context, ev tmtypes.EventDataNewBlock) {
	tmEvents := append([]tmabcitypes.Event{}, ev.ResultBeginBlock.GetEvents()...)
	tmEvents = append(tmEvents, ev.ResultEndBlock.GetEvents()...)
	events, err := EventsFromTendermint(nil, ev.Block.Header.Height, tmEvents)
	if err != nil {
		tb.logger.Error("error processing staking events", "err", err)
	}
	tb.notifyEvents(events)
}

func (tb *tendermintBackend) onEventDataTx(ctx context.Context, ev tmtypes.EventDataTx) {
	events, err := EventsFromTendermint(ev.Tx, ev.Height, ev.Result.Events)
	if err != nil {
		tb.logger.Error("error processing staking events", "err", err)
	}
	tb.notifyEvents(events)
}

func (tb *tendermintBackend) notifyEvents(events []*api.Event) {
	for _, ev := range events {
		if ev.Transfer != nil {
			tb.transferNotifier.Broadcast(ev.Transfer)
		}
		if ev.Escrow != nil {
			tb.escrowNotifier.Broadcast(ev.Escrow)
		}
		if ev.Burn != nil {
			tb.burnNotifier.Broadcast(ev.Burn)
		}
		tb.eventNotifier.Broadcast(ev)
	}
}

// EventsFromTendermint extracts staking events from tendermint events.
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
		// Ignore events that don't relate to the staking app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case bytes.Equal(key, app.KeyTakeEscrow):
				// Take escrow event.
				var e api.TakeEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt TakeEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Take: &e}}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyTransfer):
				// Transfer event.
				var e api.TransferEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt Transfer event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Transfer: &e}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyReclaimEscrow):
				// Reclaim escrow event.
				var e api.ReclaimEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt ReclaimEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Reclaim: &e}}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyAddEscrow):
				// Add escrow event.
				var e api.AddEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt AddEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Add: &e}}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyBurn):
				// Burn event.
				var e api.BurnEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt Burn event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Burn: &e}
				events = append(events, evt)
			default:
				errs = multierror.Append(errs, fmt.Errorf("staking: unknown event type: key: %s, val: %s", key, val))
			}
		}
	}

	return events, errs
}

// New constructs a new tendermint backed staking Backend instance.
func New(ctx context.Context, service service.TendermintService) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	// Configure the staking application as a fee handler.
	if err := service.SetTransactionAuthHandler(a.(abci.TransactionAuthHandler)); err != nil {
		return nil, err
	}

	tb := &tendermintBackend{
		logger:           logging.GetLogger("staking/tendermint"),
		service:          service,
		querier:          a.QueryFactory().(*app.QueryFactory),
		transferNotifier: pubsub.NewBroker(false),
		burnNotifier:     pubsub.NewBroker(false),
		escrowNotifier:   pubsub.NewBroker(false),
		eventNotifier:    pubsub.NewBroker(false),
		closedCh:         make(chan struct{}),
	}

	go tb.worker(ctx)

	return tb, nil
}
