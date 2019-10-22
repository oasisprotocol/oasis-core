// Package staking implements the staking application.
package staking

import (
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/logging"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
	stakingState "github.com/oasislabs/oasis-core/go/tendermint/apps/staking/state"
)

var (
	_ abci.Application = (*stakingApplication)(nil)
)

type stakingApplication struct {
	logger *logging.Logger

	state      *abci.ApplicationState
	timeSource epochtime.Backend
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
	if changed, epoch := app.state.EpochChanged(ctx, app.timeSource); changed {
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

		var tokens staking.Quantity
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

		if err := staking.Move(&delegator.General.Balance, &tokens, tokenAmount); err != nil {
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

	// Earned rewards.
	if err := state.AddRewards(epoch); err != nil {
		return err
	}

	return nil
}

func (app *stakingApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) error {
	return errors.New("tendermint/staking: unexpected timer")
}

func (app *stakingApplication) transfer(ctx *abci.Context, state *stakingState.MutableState, signedXfer *staking.SignedTransfer) error {
	var xfer staking.Transfer
	if err := signedXfer.Open(staking.TransferSignatureContext, &xfer); err != nil {
		app.logger.Error("Transfer: invalid signature",
			"signed_xfer", signedXfer,
		)
		return staking.ErrInvalidSignature
	}

	fromID := signedXfer.Signature.PublicKey
	from := state.Account(fromID)
	if from.General.Nonce != xfer.Nonce {
		app.logger.Error("Transfer: invalid account nonce",
			"from", fromID,
			"account_nonce", from.General.Nonce,
			"xfer_nonce", xfer.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	if fromID.Equal(xfer.To) {
		// Handle transfer to self as just a balance check.
		if from.General.Balance.Cmp(&xfer.Tokens) < 0 {
			err := staking.ErrInsufficientBalance
			app.logger.Error("Transfer: self-transfer greater than balance",
				"err", err,
				"from", fromID,
				"to", xfer.To,
				"amount", xfer.Tokens,
			)
			return err
		}
	} else {
		// Source and destination MUST be separate accounts with how
		// staking.Move is implemented.
		to := state.Account(xfer.To)
		if err := staking.Move(&to.General.Balance, &from.General.Balance, &xfer.Tokens); err != nil {
			app.logger.Error("Transfer: failed to move balance",
				"err", err,
				"from", fromID,
				"to", xfer.To,
				"amount", xfer.Tokens,
			)
			return err
		}

		state.SetAccount(xfer.To, to)
	}

	from.General.Nonce++
	state.SetAccount(fromID, from)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("Transfer: executed transfer",
			"from", fromID,
			"to", xfer.To,
			"amount", xfer.Tokens,
		)

		evt := &staking.TransferEvent{
			From:   fromID,
			To:     xfer.To,
			Tokens: xfer.Tokens,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyTransfer, cbor.Marshal(evt)))
	}

	return nil
}

func (app *stakingApplication) burn(ctx *abci.Context, state *stakingState.MutableState, signedBurn *staking.SignedBurn) error {
	var burn staking.Burn
	if err := signedBurn.Open(staking.BurnSignatureContext, &burn); err != nil {
		app.logger.Error("Burn: invalid signature",
			"signed_burn", signedBurn,
		)
		return staking.ErrInvalidSignature
	}

	id := signedBurn.Signature.PublicKey
	from := state.Account(id)
	if from.General.Nonce != burn.Nonce {
		app.logger.Error("Burn: invalid account nonce",
			"from", id,
			"account_nonce", from.General.Nonce,
			"burn_nonce", burn.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	if err := from.General.Balance.Sub(&burn.Tokens); err != nil {
		app.logger.Error("Burn: failed to burn tokens",
			"err", err,
			"from", id, "amount", burn.Tokens,
		)
		return err
	}

	totalSupply, _ := state.TotalSupply()

	from.General.Nonce++
	_ = totalSupply.Sub(&burn.Tokens)

	state.SetAccount(id, from)
	state.SetTotalSupply(totalSupply)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("Burn: burnt tokens",
			"from", id,
			"amount", burn.Tokens,
		)

		evt := &staking.BurnEvent{
			Owner:  id,
			Tokens: burn.Tokens,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyBurn, cbor.Marshal(evt)))
	}

	return nil
}

func (app *stakingApplication) addEscrow(ctx *abci.Context, state *stakingState.MutableState, signedEscrow *staking.SignedEscrow) error {
	var escrow staking.Escrow
	if err := signedEscrow.Open(staking.EscrowSignatureContext, &escrow); err != nil {
		app.logger.Error("AddEscrow: invalid signature",
			"signed_escrow", signedEscrow,
		)
		return staking.ErrInvalidSignature
	}

	// Verify delegator account nonce.
	id := signedEscrow.Signature.PublicKey
	from := state.Account(id)
	if from.General.Nonce != escrow.Nonce {
		app.logger.Error("AddEscrow: invalid account nonce",
			"from", id,
			"account_nonce", from.General.Nonce,
			"escrow_nonce", escrow.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	// Fetch escrow account.
	//
	// NOTE: Could be the same account, so make sure to not have two duplicate
	//       copies of it and overwrite it later.
	var to *staking.Account
	if id.Equal(escrow.Account) {
		to = from
	} else {
		to = state.Account(escrow.Account)
	}

	// Fetch delegation.
	delegation := state.Delegation(id, escrow.Account)

	if err := to.Escrow.Active.Deposit(&delegation.Shares, &from.General.Balance, &escrow.Tokens); err != nil {
		app.logger.Error("AddEscrow: failed to escrow tokens",
			"err", err,
			"from", id,
			"to", escrow.Account,
			"amount", escrow.Tokens,
		)
		return err
	}
	from.General.Nonce++

	// Commit accounts.
	state.SetAccount(id, from)
	if !id.Equal(escrow.Account) {
		state.SetAccount(escrow.Account, to)
	}
	// Commit delegation descriptor.
	state.SetDelegation(id, escrow.Account, delegation)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("AddEscrow: escrowed tokens",
			"from", id,
			"to", escrow.Account,
			"amount", escrow.Tokens,
		)

		evt := &staking.EscrowEvent{
			Owner:  id,
			Escrow: escrow.Account,
			Tokens: escrow.Tokens,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyAddEscrow, cbor.Marshal(evt)))
	}

	return nil
}

func (app *stakingApplication) reclaimEscrow(ctx *abci.Context, state *stakingState.MutableState, signedReclaim *staking.SignedReclaimEscrow) error {
	var reclaim staking.ReclaimEscrow
	if err := signedReclaim.Open(staking.ReclaimEscrowSignatureContext, &reclaim); err != nil {
		app.logger.Error("ReclaimEscrow: invalid signature",
			"signed_reclaim", signedReclaim,
		)
		return staking.ErrInvalidSignature
	}

	// No sense if there is nothing to reclaim.
	if reclaim.Shares.IsZero() {
		return staking.ErrInvalidArgument
	}

	// Verify delegator account nonce.
	id := signedReclaim.Signature.PublicKey
	to := state.Account(id)
	if to.General.Nonce != reclaim.Nonce {
		app.logger.Error("ReclaimEscrow: invalid account nonce",
			"to", id,
			"account_nonce", to.General.Nonce,
			"reclaim_nonce", reclaim.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	// Fetch escrow account.
	//
	// NOTE: Could be the same account, so make sure to not have two duplicate
	//       copies of it and overwrite it later.
	var from *staking.Account
	if id.Equal(reclaim.Account) {
		from = to
	} else {
		from = state.Account(reclaim.Account)
	}

	// Fetch delegation.
	delegation := state.Delegation(id, reclaim.Account)

	// Fetch debonding interval and current epoch.
	debondingInterval, err := state.DebondingInterval()
	if err != nil {
		app.logger.Error("ReclaimEscrow: failed to query debonding interval",
			"err", err,
		)
		return err
	}
	epoch, err := app.timeSource.GetEpoch(ctx.Ctx(), ctx.BlockHeight()+1)
	if err != nil {
		return err
	}

	deb := staking.DebondingDelegation{
		DebondEndTime: epoch + epochtime.EpochTime(debondingInterval),
	}

	var tokens staking.Quantity

	if err := from.Escrow.Active.Withdraw(&tokens, &delegation.Shares, &reclaim.Shares); err != nil {
		app.logger.Error("ReclaimEscrow: failed to redeem escrow shares",
			"err", err,
			"to", id,
			"from", reclaim.Account,
			"shares", reclaim.Shares,
		)
		return err
	}
	tokenAmount := tokens.Clone()

	if err := from.Escrow.Debonding.Deposit(&deb.Shares, &tokens, tokenAmount); err != nil {
		app.logger.Error("ReclaimEscrow: failed to debond shares",
			"err", err,
			"to", id,
			"from", reclaim.Account,
			"shares", reclaim.Shares,
		)
		return err
	}

	if !tokens.IsZero() {
		app.logger.Error("ReclaimEscrow: inconsistency in transferring tokens from active escrow to debonding",
			"remaining", tokens,
		)
		return staking.ErrInvalidArgument
	}

	// Include the nonce as the final disambiguator to prevent overwriting debonding
	// delegations.
	state.SetDebondingDelegation(id, reclaim.Account, to.General.Nonce, &deb)

	to.General.Nonce++
	state.SetDelegation(id, reclaim.Account, delegation)
	state.SetAccount(id, to)
	if !id.Equal(reclaim.Account) {
		state.SetAccount(reclaim.Account, from)
	}

	return nil
}

// New constructs a new staking application instance.
func New(timeSource epochtime.Backend) abci.Application {
	return &stakingApplication{
		logger:     logging.GetLogger("tendermint/staking"),
		timeSource: timeSource,
	}
}
