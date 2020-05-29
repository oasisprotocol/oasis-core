// Package staking implements the tendermint backed staking token backend.
package staking

import (
	"bytes"
	"context"
	"fmt"

	abcitypes "github.com/tendermint/tendermint/abci/types"
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
	approvalNotifier *pubsub.Broker
	burnNotifier     *pubsub.Broker
	escrowNotifier   *pubsub.Broker
	eventNotifier    *pubsub.Broker

	closedCh chan struct{}
}

// Extend the abci Event struct with the transaction hash if the event was
// the result of a transaction.  Block events have Hash set to the empty hash.
type abciEventWithHash struct {
	abcitypes.Event

	TxHash hash.Hash
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

func convertTmBlockEvents(beginBlockEvents []abcitypes.Event, endBlockEvents []abcitypes.Event) []abciEventWithHash {
	var tmEvents []abciEventWithHash
	for _, bbe := range beginBlockEvents {
		var ev abciEventWithHash
		ev.Event = bbe
		ev.TxHash.Empty()
		tmEvents = append(tmEvents, ev)
	}
	for _, ebe := range endBlockEvents {
		var ev abciEventWithHash
		ev.Event = ebe
		ev.TxHash.Empty()
		tmEvents = append(tmEvents, ev)
	}
	return tmEvents
}

func (tb *tendermintBackend) GetEvents(ctx context.Context, height int64) ([]api.Event, error) {
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

	// Decode events from block results.
	tmEvents := convertTmBlockEvents(results.BeginBlockEvents, results.EndBlockEvents)
	for txIdx, txResults := range results.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.

		// Generate hash of transaction.
		evHash := hash.NewFromBytes(txns[txIdx])

		// Append hash to each event.
		for _, tmEv := range txResults.Events {
			var ev abciEventWithHash
			ev.Event = tmEv
			ev.TxHash = evHash
			tmEvents = append(tmEvents, ev)
		}
	}
	return tb.onABCIEvents(ctx, tmEvents, height, false)
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
	events := convertTmBlockEvents(ev.ResultBeginBlock.GetEvents(), ev.ResultEndBlock.GetEvents())

	_, _ = tb.onABCIEvents(ctx, events, ev.Block.Header.Height, true)
}

func (tb *tendermintBackend) onEventDataTx(ctx context.Context, tx tmtypes.EventDataTx) {
	evHash := hash.NewFromBytes(tx.Tx)

	var events []abciEventWithHash
	for _, tmEv := range tx.Result.Events {
		var ev abciEventWithHash
		ev.Event = tmEv
		ev.TxHash = evHash
		events = append(events, ev)
	}

	_, _ = tb.onABCIEvents(ctx, events, tx.Height, true)
}

func (tb *tendermintBackend) onABCIEvents(context context.Context, tmEvents []abciEventWithHash, height int64, doBroadcast bool) ([]api.Event, error) {
	var events []api.Event
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the staking app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		eh := tmEv.TxHash

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()
			if bytes.Equal(key, app.KeyTakeEscrow) {
				// Take escrow event.
				var e api.TakeEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					tb.logger.Error("worker: failed to get take escrow event from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, fmt.Errorf("staking: corrupt TakeEscrow event: %w", err)
					}
				}

				ee := &api.EscrowEvent{Take: &e}
				evt := &api.Event{Height: height, TxHash: eh, EscrowEvent: ee}

				if doBroadcast {
					tb.escrowNotifier.Broadcast(ee)
					tb.eventNotifier.Broadcast(evt)
				} else {
					events = append(events, *evt)
				}
			} else if bytes.Equal(key, app.KeyTransfer) {
				// Transfer event.
				var e api.TransferEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					tb.logger.Error("worker: failed to get transfer event from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, fmt.Errorf("staking: corrupt Transfer event: %w", err)
					}
				}

				evt := &api.Event{Height: height, TxHash: eh, TransferEvent: &e}

				if doBroadcast {
					tb.transferNotifier.Broadcast(&e)
					tb.eventNotifier.Broadcast(evt)
				} else {
					events = append(events, *evt)
				}
			} else if bytes.Equal(key, app.KeyReclaimEscrow) {
				// Reclaim escrow event.
				var e api.ReclaimEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					tb.logger.Error("worker: failed to get reclaim escrow event from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, fmt.Errorf("staking: corrupt ReclaimEscrow event: %w", err)
					}
				}

				ee := &api.EscrowEvent{Reclaim: &e}
				evt := &api.Event{Height: height, TxHash: eh, EscrowEvent: ee}

				if doBroadcast {
					tb.escrowNotifier.Broadcast(ee)
					tb.eventNotifier.Broadcast(evt)
				} else {
					events = append(events, *evt)
				}
			} else if bytes.Equal(key, app.KeyAddEscrow) {
				// Add escrow event.
				var e api.AddEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					tb.logger.Error("worker: failed to get escrow event from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, fmt.Errorf("staking: corrupt AddEscrow event: %w", err)
					}
				}

				ee := &api.EscrowEvent{Add: &e}
				evt := &api.Event{Height: height, TxHash: eh, EscrowEvent: ee}

				if doBroadcast {
					tb.escrowNotifier.Broadcast(ee)
					tb.eventNotifier.Broadcast(evt)
				} else {
					events = append(events, *evt)
				}
			} else if bytes.Equal(key, app.KeyBurn) {
				// Burn event.
				var e api.BurnEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					tb.logger.Error("worker: failed to get burn event from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, fmt.Errorf("staking: corrupt Burn event: %w", err)
					}
				}

				evt := &api.Event{Height: height, TxHash: eh, BurnEvent: &e}

				if doBroadcast {
					tb.burnNotifier.Broadcast(&e)
					tb.eventNotifier.Broadcast(evt)
				} else {
					events = append(events, *evt)
				}
			}
		}
	}
	return events, nil
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
		approvalNotifier: pubsub.NewBroker(false),
		burnNotifier:     pubsub.NewBroker(false),
		escrowNotifier:   pubsub.NewBroker(false),
		eventNotifier:    pubsub.NewBroker(false),
		closedCh:         make(chan struct{}),
	}

	go tb.worker(ctx)

	return tb, nil
}
