// Package tendermint implements the tendermint backed staking token backend.
package tendermint

import (
	"bytes"
	"context"

	"github.com/pkg/errors"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/staking/api"
	tmapi "github.com/oasislabs/oasis-core/go/tendermint/api"
	app "github.com/oasislabs/oasis-core/go/tendermint/apps/staking"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = tmapi.BackendName

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

func (tb *tendermintBackend) Name() string {
	return api.TokenName
}

func (tb *tendermintBackend) Symbol() string {
	return api.TokenSymbol
}

func (tb *tendermintBackend) TotalSupply(ctx context.Context, height int64) (*api.Quantity, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.TotalSupply(ctx)
}

func (tb *tendermintBackend) CommonPool(ctx context.Context, height int64) (*api.Quantity, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.CommonPool(ctx)
}

func (tb *tendermintBackend) Threshold(ctx context.Context, kind api.ThresholdKind, height int64) (*api.Quantity, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Threshold(ctx, kind)
}

func (tb *tendermintBackend) Accounts(ctx context.Context, height int64) ([]signature.PublicKey, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Accounts(ctx)
}

func (tb *tendermintBackend) AccountInfo(ctx context.Context, owner signature.PublicKey, height int64) (*api.Account, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.AccountInfo(ctx, owner)
}

func (tb *tendermintBackend) DebondingDelegations(ctx context.Context, owner signature.PublicKey, height int64) (map[signature.MapKey][]*api.DebondingDelegation, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.DebondingDelegations(ctx, owner)
}

func (tb *tendermintBackend) Transfer(ctx context.Context, signedXfer *api.SignedTransfer) error {
	tx := app.Tx{
		TxTransfer: &app.TxTransfer{
			SignedTransfer: *signedXfer,
		},
	}
	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "staking: transfer transaction failed")
	}

	return nil
}

func (tb *tendermintBackend) Burn(ctx context.Context, signedBurn *api.SignedBurn) error {
	tx := app.Tx{
		TxBurn: &app.TxBurn{
			SignedBurn: *signedBurn,
		},
	}
	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "staking: burn transaction failed")
	}

	return nil
}

func (tb *tendermintBackend) AddEscrow(ctx context.Context, signedEscrow *api.SignedEscrow) error {
	tx := app.Tx{
		TxAddEscrow: &app.TxAddEscrow{
			SignedEscrow: *signedEscrow,
		},
	}
	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "staking: add escrow transaction failed")
	}

	return nil
}

func (tb *tendermintBackend) ReclaimEscrow(ctx context.Context, signedReclaim *api.SignedReclaimEscrow) error {
	tx := app.Tx{
		TxReclaimEscrow: &app.TxReclaimEscrow{
			SignedReclaimEscrow: *signedReclaim,
		},
	}
	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "staking: reclaim escrow transaction failed")
	}

	return nil
}

func (tb *tendermintBackend) SubmitEvidence(ctx context.Context, evidence api.Evidence) error {
	if evidence.Kind() != api.EvidenceKindConsensus {
		return errors.New("staking: unsupported evidence kind")
	}

	tmEvidence, ok := evidence.Unwrap().(tmtypes.Evidence)
	if !ok {
		return errors.New("staking: expected tendermint evidence, got something else")
	}

	if err := tb.service.BroadcastEvidence(ctx, tmEvidence); err != nil {
		return errors.Wrap(err, "staking: broadcast evidence failed")
	}

	return nil
}

func (tb *tendermintBackend) WatchTransfers() (<-chan *api.TransferEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.TransferEvent)
	sub := tb.transferNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (tb *tendermintBackend) WatchBurns() (<-chan *api.BurnEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.BurnEvent)
	sub := tb.burnNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (tb *tendermintBackend) WatchEscrows() (<-chan interface{}, *pubsub.Subscription) {
	sub := tb.escrowNotifier.Subscribe()
	return sub.Untyped(), sub
}

func (tb *tendermintBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
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

	tb.onABCIEvents(ctx, events, ev.Block.Header.Height)
}

func (tb *tendermintBackend) onABCIEvents(context context.Context, events []abcitypes.Event, height int64) {
	for _, tmEv := range events {
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.KeyTakeEscrow) {
				var e api.TakeEscrowEvent
				if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
					tb.logger.Error("worker: failed to get take escrow event from tag",
						"err", err,
					)
					continue
				}

				tb.escrowNotifier.Broadcast(&e)
			} else if bytes.Equal(pair.GetKey(), app.KeyTransfer) {
				var e api.TransferEvent
				if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
					tb.logger.Error("worker: failed to get transfer event from tag",
						"err", err,
					)
					continue
				}

				tb.transferNotifier.Broadcast(&e)
			} else if bytes.Equal(pair.GetKey(), app.KeyReclaimEscrow) {
				var e api.ReclaimEscrowEvent
				if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
					tb.logger.Error("worker: failed to get reclaim escrow event from tag",
						"err", err,
					)
					continue
				}

				tb.escrowNotifier.Broadcast(&e)
			} else if bytes.Equal(pair.GetKey(), app.KeyAddEscrow) {
				var e api.EscrowEvent
				if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
					tb.logger.Error("worker: failed to get escrow event from tag",
						"err", err,
					)
					continue
				}

				tb.escrowNotifier.Broadcast(&e)
			} else if bytes.Equal(pair.GetKey(), app.KeyBurn) {
				var e api.BurnEvent
				if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
					tb.logger.Error("worker: failed to get burn event from tag",
						"err", err,
					)
					continue
				}

				tb.burnNotifier.Broadcast(&e)
			}
		}
	}
}

func (tb *tendermintBackend) onEventDataTx(ctx context.Context, tx tmtypes.EventDataTx) {
	tb.onABCIEvents(ctx, tx.Result.Events, tx.Height)
}

// New constructs a new tendermint backed staking Backend instance.
func New(
	ctx context.Context,
	timeSource epochtime.Backend,
	debugGenesisState *api.Genesis,
	service service.TendermintService,
) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	a := app.New(timeSource, debugGenesisState)
	if err := service.RegisterApplication(a); err != nil {
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
