// Package staking implements the tendermint backed staking token backend.
package staking

import (
	"bytes"
	"context"
	"fmt"

	abcitypes "github.com/tendermint/tendermint/abci/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/staking/api"
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

func (tb *tendermintBackend) Accounts(ctx context.Context, height int64) ([]signature.PublicKey, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Accounts(ctx)
}

func (tb *tendermintBackend) AccountInfo(ctx context.Context, query *api.OwnerQuery) (*api.Account, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.AccountInfo(ctx, query.Owner)
}

func (tb *tendermintBackend) Delegations(ctx context.Context, query *api.OwnerQuery) (map[signature.PublicKey]*api.Delegation, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Delegations(ctx, query.Owner)
}

func (tb *tendermintBackend) DebondingDelegations(ctx context.Context, query *api.OwnerQuery) (map[signature.PublicKey][]*api.DebondingDelegation, error) {
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

	// Decode events from block results.
	tmEvents := append(results.Results.BeginBlock.GetEvents(), results.Results.EndBlock.GetEvents()...)
	for _, txResults := range results.Results.DeliverTx {
		tmEvents = append(tmEvents, txResults.GetEvents()...)
	}
	return tb.onABCIEvents(ctx, tmEvents, height, false)
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
	events := append([]abcitypes.Event{}, ev.ResultBeginBlock.GetEvents()...)
	events = append(events, ev.ResultEndBlock.GetEvents()...)

	_, _ = tb.onABCIEvents(ctx, events, ev.Block.Header.Height, true)
}

func (tb *tendermintBackend) onEventDataTx(ctx context.Context, tx tmtypes.EventDataTx) {
	_, _ = tb.onABCIEvents(ctx, tx.Result.Events, tx.Height, true)
}

func (tb *tendermintBackend) onABCIEvents(context context.Context, tmEvents []abcitypes.Event, height int64, doBroadcast bool) ([]api.Event, error) {
	var events []api.Event
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the staking app.
		if tmEv.GetType() != app.EventType {
			continue
		}

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

				if doBroadcast {
					tb.escrowNotifier.Broadcast(ee)
				} else {
					events = append(events, api.Event{EscrowEvent: ee})
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

				if doBroadcast {
					tb.transferNotifier.Broadcast(&e)
				} else {
					events = append(events, api.Event{TransferEvent: &e})
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

				if doBroadcast {
					tb.escrowNotifier.Broadcast(ee)
				} else {
					events = append(events, api.Event{EscrowEvent: ee})
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

				if doBroadcast {
					tb.escrowNotifier.Broadcast(ee)
				} else {
					events = append(events, api.Event{EscrowEvent: ee})
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

				if doBroadcast {
					tb.burnNotifier.Broadcast(&e)
				} else {
					events = append(events, api.Event{BurnEvent: &e})
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
		closedCh:         make(chan struct{}),
	}

	go tb.worker(ctx)

	return tb, nil
}
