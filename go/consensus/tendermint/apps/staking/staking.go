// Package staking implements the staking application.
package staking

import (
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

var (
	_ abci.Application = (*stakingApplication)(nil)
)

type stakingApplication struct {
	logger *logging.Logger

	state *abci.ApplicationState
}

func (app *stakingApplication) Name() string {
	return AppName
}

func (app *stakingApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *stakingApplication) Blessed() bool {
	return false
}

func (app *stakingApplication) Dependencies() []string {
	return nil
}

func (app *stakingApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *stakingApplication) OnCleanup() {
}

func (app *stakingApplication) SetOption(types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *stakingApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// Disburse fees from previous block.
	if err := app.disburseFees(ctx, request.GetLastCommitInfo()); err != nil {
		return fmt.Errorf("staking: failed to disburse fees: %w", err)
	}

	// Iterate over any submitted evidence of a validator misbehaving. Note that
	// the actual evidence has already been verified by Tendermint to be valid.
	for _, evidence := range request.ByzantineValidators {
		switch evidence.Type {
		case tmtypes.ABCIEvidenceTypeDuplicateVote:
			if err := app.onEvidenceDoubleSign(ctx, evidence.Validator.Address, evidence.Height, evidence.Time, evidence.Validator.Power); err != nil {
				return err
			}
		default:
			app.logger.Warn("ignoring unknown evidence type",
				"evidence_type", evidence.Type,
			)
		}
	}

	return nil
}

func (app *stakingApplication) ExecuteTx(ctx *abci.Context, rawTx []byte) error {
	var tx Tx
	if err := cbor.Unmarshal(rawTx, &tx); err != nil {
		app.logger.Error("failed to unmarshal",
			"err", err,
			"tx", hex.EncodeToString(rawTx),
		)
		return errors.Wrap(err, "staking/tendermint: failed to unmarshal tx")
	}

	state := stakingState.NewMutableState(ctx.State())

	if tx.TxTransfer != nil {
		return app.transfer(ctx, state, &tx.TxTransfer.SignedTransfer)
	} else if tx.TxBurn != nil {
		return app.burn(ctx, state, &tx.TxBurn.SignedBurn)
	} else if tx.TxAddEscrow != nil {
		return app.addEscrow(ctx, state, &tx.TxAddEscrow.SignedEscrow)
	} else if tx.TxReclaimEscrow != nil {
		return app.reclaimEscrow(ctx, state, &tx.TxReclaimEscrow.SignedReclaimEscrow)
	}
	return staking.ErrInvalidArgument
}

func (app *stakingApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *stakingApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	// Persist any block fees so we can transfer them in the next block.
	stakingState.PersistBlockFees(ctx)

	if changed, epoch := app.state.EpochChanged(ctx); changed {
		return types.ResponseEndBlock{}, app.onEpochChange(ctx, epoch)
	}
	return types.ResponseEndBlock{}, nil
}

func (app *stakingApplication) onEpochChange(ctx *abci.Context, epoch epochtime.EpochTime) error {
	state := stakingState.NewMutableState(ctx.State())

	// Delegation unbonding after debonding period elapses.
	for _, e := range state.ExpiredDebondingQueue(epoch) {
		deb := e.Delegation
		shareAmount := deb.Shares.Clone()
		delegator := state.Account(e.DelegatorID)
		// NOTE: Could be the same account, so make sure to not have two duplicate
		//       copies of it and overwrite it later.
		var escrow *staking.Account
		if e.DelegatorID.Equal(e.EscrowID) {
			escrow = delegator
		} else {
			escrow = state.Account(e.EscrowID)
		}

		var tokens quantity.Quantity
		if err := escrow.Escrow.Debonding.Withdraw(&tokens, &deb.Shares, shareAmount); err != nil {
			app.logger.Error("failed to redeem debonding shares",
				"err", err,
				"escrow_id", e.EscrowID,
				"delegator_id", e.DelegatorID,
				"shares", deb.Shares,
			)
			return errors.Wrap(err, "staking/tendermint: failed to redeem debonding shares")
		}
		tokenAmount := tokens.Clone()

		if err := quantity.Move(&delegator.General.Balance, &tokens, tokenAmount); err != nil {
			app.logger.Error("failed to move debonded tokens",
				"err", err,
				"escrow_id", e.EscrowID,
				"delegator_id", e.DelegatorID,
				"shares", deb.Shares,
			)
			return errors.Wrap(err, "staking/tendermint: failed to redeem debonding shares")
		}

		// Update state.
		state.RemoveFromDebondingQueue(e.Epoch, e.DelegatorID, e.EscrowID, e.Seq)
		state.SetDebondingDelegation(e.DelegatorID, e.EscrowID, e.Seq, nil)
		state.SetAccount(e.DelegatorID, delegator)
		if !e.DelegatorID.Equal(e.EscrowID) {
			state.SetAccount(e.EscrowID, escrow)
		}

		app.logger.Debug("released tokens",
			"escrow_id", e.EscrowID,
			"delegator_id", e.DelegatorID,
			"amount", tokenAmount,
		)

		evt := staking.ReclaimEscrowEvent{
			Owner:  e.DelegatorID,
			Escrow: e.EscrowID,
			Tokens: *tokenAmount,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyReclaimEscrow, cbor.Marshal(evt)))
	}

	return nil
}

func (app *stakingApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) error {
	return errors.New("tendermint/staking: unexpected timer")
}

// New constructs a new staking application instance.
func New() abci.Application {
	return &stakingApplication{
		logger: logging.GetLogger("tendermint/staking"),
	}
}
