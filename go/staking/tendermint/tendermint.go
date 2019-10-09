// Package tendermint implements the tendermint backed staking token backend.
package tendermint

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
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

	transferNotifier *pubsub.Broker
	approvalNotifier *pubsub.Broker
	burnNotifier     *pubsub.Broker
	escrowNotifier   *pubsub.Broker

	closedCh chan struct{}
}

func (b *tendermintBackend) Name() string {
	return api.TokenName
}

func (b *tendermintBackend) Symbol() string {
	return api.TokenSymbol
}

func (b *tendermintBackend) TotalSupply(ctx context.Context) (*api.Quantity, error) {
	response, err := b.service.Query(app.QueryTotalSupply, nil, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: total supply query failed")
	}

	var data api.Quantity
	if err = cbor.Unmarshal(response, &data); err != nil {
		return nil, errors.Wrap(err, "staking: total supply malformed response")
	}

	return &data, nil
}

func (b *tendermintBackend) CommonPool(ctx context.Context) (*api.Quantity, error) {
	response, err := b.service.Query(app.QueryCommonPool, nil, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: common pool query failed")
	}

	var data api.Quantity
	if err = cbor.Unmarshal(response, &data); err != nil {
		return nil, errors.Wrap(err, "staking: common pool malformed response")
	}

	return &data, nil
}

func (b *tendermintBackend) Threshold(ctx context.Context, kind api.ThresholdKind) (*api.Quantity, error) {
	response, err := b.service.Query(app.QueryThresholds, nil, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: thresholds query failed")
	}

	data := make(map[api.ThresholdKind]api.Quantity)
	if err = cbor.Unmarshal(response, &data); err != nil {
		return nil, errors.Wrap(err, "staking: thresholds malformed response")
	}
	qty := data[kind]

	return &qty, nil
}

func (b *tendermintBackend) Accounts(ctx context.Context) ([]signature.PublicKey, error) {
	response, err := b.service.Query(app.QueryAccounts, nil, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: accounts query failed")
	}

	var data []signature.PublicKey
	if err = cbor.Unmarshal(response, &data); err != nil {
		return nil, errors.Wrap(err, "staking: accounts query malformed response")
	}

	return data, nil
}

func (b *tendermintBackend) AccountInfo(ctx context.Context, owner signature.PublicKey) (*api.Account, error) {
	query := tmapi.QueryGetByIDRequest{
		ID: owner,
	}
	response, err := b.service.Query(app.QueryAccountInfo, query, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: account info query failed")
	}

	var a api.Account
	if err := cbor.Unmarshal(response, &a); err != nil {
		return nil, errors.Wrap(err, "staking: account info query malformed response")
	}

	return &a, nil
}

func (b *tendermintBackend) DebondingDelegations(ctx context.Context, owner signature.PublicKey) (map[signature.MapKey][]*api.DebondingDelegation, error) {
	query := tmapi.QueryGetByIDRequest{
		ID: owner,
	}
	response, err := b.service.Query(app.QueryDebondingDelegations, query, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: debonding delegations query failed")
	}

	var debs map[signature.MapKey][]*api.DebondingDelegation
	if err := cbor.Unmarshal(response, &debs); err != nil {
		return nil, errors.Wrap(err, "staking: debonding delegations query malformed response")
	}

	return debs, nil
}

func (b *tendermintBackend) Transfer(ctx context.Context, signedXfer *api.SignedTransfer) error {
	tx := app.Tx{
		TxTransfer: &app.TxTransfer{
			SignedTransfer: *signedXfer,
		},
	}
	if err := b.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "staking: transfer transaction failed")
	}

	return nil
}

func (b *tendermintBackend) Burn(ctx context.Context, signedBurn *api.SignedBurn) error {
	tx := app.Tx{
		TxBurn: &app.TxBurn{
			SignedBurn: *signedBurn,
		},
	}
	if err := b.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "staking: burn transaction failed")
	}

	return nil
}

func (b *tendermintBackend) AddEscrow(ctx context.Context, signedEscrow *api.SignedEscrow) error {
	tx := app.Tx{
		TxAddEscrow: &app.TxAddEscrow{
			SignedEscrow: *signedEscrow,
		},
	}
	if err := b.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "staking: add escrow transaction failed")
	}

	return nil
}

func (b *tendermintBackend) ReclaimEscrow(ctx context.Context, signedReclaim *api.SignedReclaimEscrow) error {
	tx := app.Tx{
		TxReclaimEscrow: &app.TxReclaimEscrow{
			SignedReclaimEscrow: *signedReclaim,
		},
	}
	if err := b.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "staking: reclaim escrow transaction failed")
	}

	return nil
}

func (b *tendermintBackend) WatchTransfers() (<-chan *api.TransferEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.TransferEvent)
	sub := b.transferNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (b *tendermintBackend) WatchBurns() (<-chan *api.BurnEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.BurnEvent)
	sub := b.burnNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (b *tendermintBackend) WatchEscrows() (<-chan interface{}, *pubsub.Subscription) {
	sub := b.escrowNotifier.Subscribe()
	return sub.Untyped(), sub
}

func (b *tendermintBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	response, err := b.service.Query(app.QueryGenesis, nil, height)
	if err != nil {
		return nil, errors.Wrap(err, "staking/tendermint: genesis query failed")
	}

	var genesis api.Genesis
	if err = cbor.Unmarshal(response, &genesis); err != nil {
		return nil, errors.Wrap(err, "staking/tendermint: genesis malformed response")
	}

	return &genesis, nil
}

func (b *tendermintBackend) Cleanup() {
	<-b.closedCh
}

func (b *tendermintBackend) worker(ctx context.Context) {
	defer close(b.closedCh)

	sub, err := b.service.Subscribe("staking-worker", app.QueryUpdate)
	if err != nil {
		b.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer b.service.Unsubscribe("staking-worker", app.QueryUpdate) // nolint: errcheck

	for {
		var event interface{}

		select {
		case msg := <-sub.Out():
			event = msg.Data()
		case <-sub.Cancelled():
			b.logger.Debug("worker: terminating, subscription closed")
			return
		case <-ctx.Done():
			return
		}

		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			b.onEventDataNewBlock(ctx, ev)
		case tmtypes.EventDataTx:
			b.onEventDataTx(ctx, ev)
		default:
		}
	}
}

func (b *tendermintBackend) onEventDataNewBlock(ctx context.Context, ev tmtypes.EventDataNewBlock) {
	events := ev.ResultBeginBlock.GetEvents()
	events = append(events, ev.ResultEndBlock.GetEvents()...)

	for _, tmEv := range events {
		if tmEv.GetType() != tmapi.EventTypeOasis {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.TagTakeEscrow) {
				var e api.TakeEscrowEvent
				if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
					b.logger.Error("worker: failed to get take escrow event from tag",
						"err", err,
					)
					continue
				}

				b.escrowNotifier.Broadcast(&e)
			} else if bytes.Equal(pair.GetKey(), app.TagTransfer) {
				var e api.TransferEvent
				if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
					b.logger.Error("worker: failed to get transfer event from tag",
						"err", err,
					)
					continue
				}

				b.transferNotifier.Broadcast(&e)
			} else if bytes.Equal(pair.GetKey(), app.TagReclaimEscrow) {
				var e api.ReclaimEscrowEvent
				if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
					b.logger.Error("worker: failed to get reclaim escrow event from tag",
						"err", err,
					)
					continue
				}

				b.escrowNotifier.Broadcast(&e)
			}
		}
	}
}

func (b *tendermintBackend) onEventDataTx(ctx context.Context, ev tmtypes.EventDataTx) {
	output := &app.Output{}
	if err := cbor.Unmarshal(ev.Result.GetData(), output); err != nil {
		b.logger.Error("worker: malformed transaction ouytput",
			"tx", hex.EncodeToString(ev.Result.GetData()),
		)
		return
	}

	if e := output.OutputTransfer; e != nil {
		b.transferNotifier.Broadcast(e)
	} else if e := output.OutputBurn; e != nil {
		b.burnNotifier.Broadcast(e)
	} else if e := output.OutputAddEscrow; e != nil {
		b.escrowNotifier.Broadcast(e)
	}
}

// New constructs a new tendermint backed staking Backend instance.
func New(
	ctx context.Context,
	timeSource epochtime.Backend,
	debugGenesisState *api.Genesis,
	service service.TendermintService,
) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	app := app.New(timeSource, debugGenesisState)
	if err := service.RegisterApplication(app); err != nil {
		return nil, err
	}

	b := &tendermintBackend{
		logger:           logging.GetLogger("staking/tendermint"),
		service:          service,
		transferNotifier: pubsub.NewBroker(false),
		approvalNotifier: pubsub.NewBroker(false),
		burnNotifier:     pubsub.NewBroker(false),
		escrowNotifier:   pubsub.NewBroker(false),
		closedCh:         make(chan struct{}),
	}

	go b.worker(ctx)

	return b, nil
}
