// Package tendermint implements the tendermint backed staking token backend.
package tendermint

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/staking/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/staking"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = "tendermint"

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
	return "Buffycoin"
}

func (b *tendermintBackend) Symbol() string {
	return "BUF"
}

func (b *tendermintBackend) TotalSupply(ctx context.Context) (*api.Quantity, error) {
	response, err := b.service.Query(app.QueryTotalSupply, nil, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: total supply query failed")
	}

	var data api.Quantity
	if err := cbor.Unmarshal(response, &data); err != nil {
		return nil, errors.Wrap(err, "staking: total supply malformed response")
	}

	return &data, nil
}

func (b *tendermintBackend) Accounts(ctx context.Context) ([]signature.PublicKey, error) {
	response, err := b.service.Query(app.QueryAccounts, nil, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: accounts query failed")
	}

	var data []signature.PublicKey
	if err := cbor.Unmarshal(response, &data); err != nil {
		return nil, errors.Wrap(err, "staking: accounts query malformed response")
	}

	return data, nil
}

func (b *tendermintBackend) AccountInfo(ctx context.Context, owner signature.PublicKey) (*api.Quantity, *api.Quantity, uint64, error) {
	query := tmapi.QueryGetByIDRequest{
		ID: owner,
	}
	response, err := b.service.Query(app.QueryAccountInfo, query, 0)
	if err != nil {
		return nil, nil, 0, errors.Wrap(err, "staking: account info query failed")
	}

	var data app.QueryAccountInfoResponse
	if err := cbor.Unmarshal(response, &data); err != nil {
		return nil, nil, 0, errors.Wrap(err, "staking: account info query malformed response")
	}

	return &data.GeneralBalance, &data.EscrowBalance, data.Nonce, nil
}

func (b *tendermintBackend) Transfer(ctx context.Context, signedXfer *api.SignedTransfer) error {
	tx := app.Tx{
		TxTransfer: &app.TxTransfer{
			SignedTransfer: *signedXfer,
		},
	}
	if err := b.service.BroadcastTx(app.TransactionTag, tx); err != nil {
		return errors.Wrap(err, "staking: transfer transaction failed")
	}

	return nil
}

func (b *tendermintBackend) Allowance(ctx context.Context, owner, spender signature.PublicKey) (*api.Quantity, error) {
	query := app.QueryAllowanceRequest{
		Owner:   owner,
		Spender: spender,
	}
	response, err := b.service.Query(app.QueryAllowance, query, 0)
	if err != nil {
		return nil, errors.Wrap(err, "staking: allowance query failed")
	}

	var data api.Quantity
	if err := cbor.Unmarshal(response, &data); err != nil {
		return nil, errors.Wrap(err, "staking: allowance malformed response")
	}

	return &data, nil
}

func (b *tendermintBackend) Approve(ctx context.Context, signedApproval *api.SignedApproval) error {
	tx := app.Tx{
		TxApprove: &app.TxApprove{
			SignedApproval: *signedApproval,
		},
	}
	if err := b.service.BroadcastTx(app.TransactionTag, tx); err != nil {
		return errors.Wrap(err, "staking: approve transaction failed")
	}

	return nil
}

func (b *tendermintBackend) Withdraw(ctx context.Context, signedWithdrawal *api.SignedWithdrawal) error {
	tx := app.Tx{
		TxWithdraw: &app.TxWithdraw{
			SignedWithdrawal: *signedWithdrawal,
		},
	}
	if err := b.service.BroadcastTx(app.TransactionTag, tx); err != nil {
		return errors.Wrap(err, "staking: withdraw transaction failed")
	}

	return nil
}

func (b *tendermintBackend) Burn(ctx context.Context, signedBurn *api.SignedBurn) error {
	tx := app.Tx{
		TxBurn: &app.TxBurn{
			SignedBurn: *signedBurn,
		},
	}
	if err := b.service.BroadcastTx(app.TransactionTag, tx); err != nil {
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
	if err := b.service.BroadcastTx(app.TransactionTag, tx); err != nil {
		return errors.Wrap(err, "staking: add escrow transaction failed")
	}

	return nil
}

func (b *tendermintBackend) WatchTransfers() (<-chan *api.TransferEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.TransferEvent)
	sub := b.transferNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (b *tendermintBackend) WatchApprovals() (<-chan *api.ApprovalEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.ApprovalEvent)
	sub := b.approvalNotifier.Subscribe()
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

func (b *tendermintBackend) Cleanup() {
	<-b.closedCh
}

func (b *tendermintBackend) worker(ctx context.Context) {
	defer close(b.closedCh)

	txChannel := make(chan interface{})
	if err := b.service.Subscribe(ctx, "staking-worker", app.QueryApp, txChannel); err != nil {
		b.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer b.service.Unsubscribe(ctx, "staking-worker", app.QueryApp) // nolint: errcheck

	for {
		var (
			event interface{}
			ok    bool
		)

		select {
		case event, ok = <-txChannel:
			if !ok {
				return
			}
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
	tags := ev.ResultBeginBlock.GetTags()
	tags = append(tags, ev.ResultEndBlock.GetTags()...)

	for _, pair := range tags {
		if bytes.Equal(pair.GetKey(), app.TagTakeEscrow) {
			var e api.TakeEscrowEvent
			if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
				b.logger.Error("worker: failed to get take escrow event from tag",
					"err", err,
				)
				continue
			}

			b.escrowNotifier.Broadcast(&e)
		} else if bytes.Equal(pair.GetKey(), app.TagReleaseEscrow) {
			var e api.ReleaseEscrowEvent
			if err := cbor.Unmarshal(pair.GetValue(), &e); err != nil {
				b.logger.Error("worker: failed to get release escrow event from tag",
					"err", err,
				)
				continue
			}

			b.escrowNotifier.Broadcast(&e)
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
	} else if e := output.OutputApprove; e != nil {
		b.approvalNotifier.Broadcast(e)
	} else if e := output.OutputBurn; e != nil {
		b.burnNotifier.Broadcast(e)
	} else if e := output.OutputAddEscrow; e != nil {
		b.escrowNotifier.Broadcast(e)
	}
}

// New constructs a new tendermint backed staking Backend instance.
func New(ctx context.Context, debugGenesisState *api.GenesisState, service service.TendermintService) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	app := app.New(debugGenesisState)
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
