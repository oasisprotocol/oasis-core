// Package staking implements the staking application.
package staking

import (
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

var (
	_ abci.Application = (*stakingApplication)(nil)
)

type stakingApplication struct {
	logger *logging.Logger

	state      *abci.ApplicationState
	timeSource epochtime.Backend

	debugGenesisState *staking.Genesis
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

	state := NewMutableState(ctx.State())

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
	if changed, epoch := app.state.EpochChanged(app.timeSource); changed {
		return types.ResponseEndBlock{}, app.onEpochChange(ctx, epoch)
	}
	return types.ResponseEndBlock{}, nil
}

func (app *stakingApplication) onEpochChange(ctx *abci.Context, epoch epochtime.EpochTime) error {
	state := NewMutableState(ctx.State())

	// Delegation unbonding after debonding period elapses.
	for _, e := range state.expiredDebondingQueue(epoch) {
		deb := e.delegation
		delegator := state.account(e.delegatorID)
		// NOTE: Could be the same account, so make sure to not have two duplicate
		//       copies of it and overwrite it later.
		var escrow *staking.Account
		if e.delegatorID.Equal(e.escrowID) {
			escrow = delegator
		} else {
			escrow = state.account(e.escrowID)
		}

		// Compute amount of debonded tokens.
		tokens, err := staking.TokensForShares(&escrow.Escrow, &deb.Shares)
		if err != nil {
			app.logger.Error("failed to compute amount of tokens from shares",
				"err", err,
				"escrow_id", e.escrowID,
				"delegator_id", e.delegatorID,
				"shares", deb.Shares,
			)
			return errors.Wrap(err, "staking/tendermint: failed to compute amount of tokens")
		}
		// Update number of total shares.
		if err := escrow.Escrow.TotalShares.Sub(&deb.Shares); err != nil {
			app.logger.Error("failed to subtract total shares",
				"err", err,
				"escrow_id", e.escrowID,
				"delegator_id", e.delegatorID,
				"shares", deb.Shares,
				"total_shares", escrow.Escrow.TotalShares,
			)
			return errors.Wrap(err, "staking/tendermint: failed to subtract total shares")
		}
		// Update number of debonding shares.
		if err := escrow.Escrow.DebondingShares.Sub(&deb.Shares); err != nil {
			app.logger.Error("failed to subtract debonding shares",
				"err", err,
				"escrow_id", e.escrowID,
				"delegator_id", e.delegatorID,
				"shares", deb.Shares,
				"debonding_shares", escrow.Escrow.DebondingShares,
			)
			return errors.Wrap(err, "staking/tendermint: failed to subtract debonding shares")
		}
		// Transfer tokens from escrow account.
		if err := staking.Move(&delegator.General.Balance, &escrow.Escrow.Balance, tokens); err != nil {
			app.logger.Error("failed to move balance",
				"err", err,
				"escrow_id", e.escrowID,
				"delegator_id", e.delegatorID,
				"amount", tokens,
			)
			return errors.Wrap(err, "staking/tendermint: failed to move balance")
		}

		// Update state.
		state.removeFromDebondingQueue(e.epoch, e.delegatorID, e.escrowID, e.seq)
		state.setDebondingDelegation(e.delegatorID, e.escrowID, e.seq, nil)
		state.setAccount(e.delegatorID, delegator)
		if !e.delegatorID.Equal(e.escrowID) {
			state.setAccount(e.escrowID, escrow)
		}

		app.logger.Debug("released tokens",
			"escrow_id", e.escrowID,
			"delegator_id", e.delegatorID,
			"amount", tokens,
		)

		evt := staking.ReclaimEscrowEvent{
			Owner:  e.delegatorID,
			Escrow: e.escrowID,
			Tokens: *tokens,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyReclaimEscrow, cbor.Marshal(evt)))
	}
	return nil
}

func (app *stakingApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) error {
	return errors.New("tendermint/staking: unexpected timer")
}

func (app *stakingApplication) transfer(ctx *abci.Context, state *MutableState, signedXfer *staking.SignedTransfer) error {
	var xfer staking.Transfer
	if err := signedXfer.Open(staking.TransferSignatureContext, &xfer); err != nil {
		app.logger.Error("Transfer: invalid signature",
			"signed_xfer", signedXfer,
		)
		return staking.ErrInvalidSignature
	}

	fromID := signedXfer.Signature.PublicKey
	from := state.account(fromID)
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
		to := state.account(xfer.To)
		if err := staking.Move(&to.General.Balance, &from.General.Balance, &xfer.Tokens); err != nil {
			app.logger.Error("Transfer: failed to move balance",
				"err", err,
				"from", fromID,
				"to", xfer.To,
				"amount", xfer.Tokens,
			)
			return err
		}

		state.setAccount(xfer.To, to)
	}

	from.General.Nonce++
	state.setAccount(fromID, from)

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

func (app *stakingApplication) burn(ctx *abci.Context, state *MutableState, signedBurn *staking.SignedBurn) error {
	var burn staking.Burn
	if err := signedBurn.Open(staking.BurnSignatureContext, &burn); err != nil {
		app.logger.Error("Burn: invalid signature",
			"signed_burn", signedBurn,
		)
		return staking.ErrInvalidSignature
	}

	id := signedBurn.Signature.PublicKey
	from := state.account(id)
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

	totalSupply, _ := state.totalSupply()

	from.General.Nonce++
	_ = totalSupply.Sub(&burn.Tokens)

	state.setAccount(id, from)
	state.setTotalSupply(totalSupply)

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

func (app *stakingApplication) addEscrow(ctx *abci.Context, state *MutableState, signedEscrow *staking.SignedEscrow) error {
	var escrow staking.Escrow
	if err := signedEscrow.Open(staking.EscrowSignatureContext, &escrow); err != nil {
		app.logger.Error("AddEscrow: invalid signature",
			"signed_escrow", signedEscrow,
		)
		return staking.ErrInvalidSignature
	}

	// Verify delegator account nonce.
	id := signedEscrow.Signature.PublicKey
	from := state.account(id)
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
		to = state.account(escrow.Account)
	}

	// Fetch delegation.
	delegation := state.delegation(id, escrow.Account)

	// Issue shares.
	if _, err := staking.IssueShares(&to.Escrow, &escrow.Tokens, delegation); err != nil {
		app.logger.Error("AddEscrow: failed to escrow tokens",
			"err", err,
			"from", id,
			"to", escrow.Account,
			"amount", escrow.Tokens,
		)
		return err
	}

	// Remove tokens from the delegator account and put them into escrow.
	if err := staking.Move(&to.Escrow.Balance, &from.General.Balance, &escrow.Tokens); err != nil {
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
	state.setAccount(id, from)
	if !id.Equal(escrow.Account) {
		state.setAccount(escrow.Account, to)
	}
	// Commit delegation descriptor.
	state.setDelegation(id, escrow.Account, delegation)

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

func (app *stakingApplication) reclaimEscrow(ctx *abci.Context, state *MutableState, signedReclaim *staking.SignedReclaimEscrow) error {
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
	to := state.account(id)
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
		from = state.account(reclaim.Account)
	}

	// Fetch delegation.
	delegation := state.delegation(id, reclaim.Account)

	// Update delegated shares.
	if err := delegation.Shares.Sub(&reclaim.Shares); err != nil {
		app.logger.Error("ReclaimEscrow: not enough shares",
			"to", id,
			"from", reclaim.Account,
			"shares", reclaim.Shares,
			"delegation_shares", delegation.Shares,
		)
		return staking.ErrInsufficientBalance
	}
	// Update the amount of shares undergoing debonding.
	if err := from.Escrow.DebondingShares.Add(&reclaim.Shares); err != nil {
		app.logger.Error("ReclaimEscrow: failed to update debonding shares",
			"err", err,
		)
		return err
	}

	// Fetch debonding interval and current epoch.
	debondingInterval, err := state.debondingInterval()
	if err != nil {
		app.logger.Error("ReclaimEscrow: failed to query debonding interval",
			"err", err,
		)
		return err
	}
	epoch, err := app.timeSource.GetEpoch(context.Background(), app.state.BlockHeight())
	if err != nil {
		return err
	}

	deb := staking.DebondingDelegation{
		Shares:        reclaim.Shares,
		DebondEndTime: epoch + epochtime.EpochTime(debondingInterval),
	}
	// Include the nonce as the final disambiguator to prevent overwriting debonding
	// delegations.
	state.setDebondingDelegation(id, reclaim.Account, to.General.Nonce, &deb)

	to.General.Nonce++
	state.setDelegation(id, reclaim.Account, delegation)
	state.setAccount(id, to)
	if !id.Equal(reclaim.Account) {
		state.setAccount(reclaim.Account, from)
	}

	return nil
}

// EnsureSufficientStake ensures that the account owned by id has sufficient
// stake to meet the sum of the thresholds specified.  The thresholds vector
// can have multiple instances of the same threshold kind specified, in which
// case it will be factored in repeatedly.
func EnsureSufficientStake(ctx *abci.Context, id signature.PublicKey, thresholds []staking.ThresholdKind) error {
	sc, err := NewStakeCache(ctx)
	if err != nil {
		return err
	}
	return sc.EnsureSufficientStake(id, thresholds)
}

// StakeCache is a lookup cache for escrow balances and thresholds that
// can be used in lieu of repeated queries to `EnsureSufficientStake` at a
// given height.  This should be favored when repeated queries are going to
// be made.
type StakeCache struct {
	ctx *abci.Context

	thresholds map[staking.ThresholdKind]staking.Quantity
	balances   map[signature.MapKey]*staking.Quantity
}

// EnsureSufficientStake ensures that the account owned by id has sufficient
// stake to meet the sum of the thresholds specified.  The thresholds vector
// can have multiple instances of the same threshold kind specified, in which
// case it will be factored in repeatedly.
func (sc *StakeCache) EnsureSufficientStake(id signature.PublicKey, thresholds []staking.ThresholdKind) error {
	escrowBalance := sc.balances[id.ToMapKey()]
	if escrowBalance == nil {
		state := NewMutableState(sc.ctx.State())
		escrowBalance = state.EscrowBalance(id)
		sc.balances[id.ToMapKey()] = escrowBalance
	}

	var targetThreshold staking.Quantity
	for _, v := range thresholds {
		qty := sc.thresholds[v]
		if err := targetThreshold.Add(&qty); err != nil {
			return errors.Wrap(err, "staking/tendermint: failed to accumulate threshold")
		}
	}

	if escrowBalance.Cmp(&targetThreshold) < 0 {
		return staking.ErrInsufficientStake
	}

	return nil
}

// NewStakeCache creates a new staking lookup cache.
func NewStakeCache(ctx *abci.Context) (*StakeCache, error) {
	state := NewMutableState(ctx.State())

	thresholds, err := state.Thresholds()
	if err != nil {
		return nil, errors.Wrap(err, "staking/tendermint: failed to query thresholds")
	}

	return &StakeCache{
		ctx:        ctx,
		thresholds: thresholds,
		balances:   make(map[signature.MapKey]*staking.Quantity),
	}, nil
}

// New constructs a new staking application instance.
func New(timeSource epochtime.Backend, debugGenesisState *staking.Genesis) abci.Application {
	return &stakingApplication{
		logger:            logging.GetLogger("tendermint/staking"),
		timeSource:        timeSource,
		debugGenesisState: debugGenesisState,
	}
}
