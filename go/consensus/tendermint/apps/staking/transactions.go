package staking

import (
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func (app *stakingApplication) transfer(ctx *abci.Context, state *stakingState.MutableState, xfer *staking.Transfer) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err := ctx.Gas().UseGas(1, staking.GasOpTransfer, params.GasCosts); err != nil {
		return err
	}

	fromID := ctx.TxSigner()
	from := state.Account(fromID)

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
		// quantity.Move is implemented.
		to := state.Account(xfer.To)
		if err := quantity.Move(&to.General.Balance, &from.General.Balance, &xfer.Tokens); err != nil {
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

	state.SetAccount(fromID, from)

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

	return nil
}

func (app *stakingApplication) burn(ctx *abci.Context, state *stakingState.MutableState, burn *staking.Burn) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err := ctx.Gas().UseGas(1, staking.GasOpBurn, params.GasCosts); err != nil {
		return err
	}

	id := ctx.TxSigner()
	from := state.Account(id)

	if err := from.General.Balance.Sub(&burn.Tokens); err != nil {
		app.logger.Error("Burn: failed to burn tokens",
			"err", err,
			"from", id, "amount", burn.Tokens,
		)
		return err
	}

	totalSupply, _ := state.TotalSupply()

	_ = totalSupply.Sub(&burn.Tokens)

	state.SetAccount(id, from)
	state.SetTotalSupply(totalSupply)

	app.logger.Debug("Burn: burnt tokens",
		"from", id,
		"amount", burn.Tokens,
	)

	evt := &staking.BurnEvent{
		Owner:  id,
		Tokens: burn.Tokens,
	}
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyBurn, cbor.Marshal(evt)))

	return nil
}

func (app *stakingApplication) addEscrow(ctx *abci.Context, state *stakingState.MutableState, escrow *staking.Escrow) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err := ctx.Gas().UseGas(1, staking.GasOpAddEscrow, params.GasCosts); err != nil {
		return err
	}

	// Check if sender provided at least a minimum amount of tokens.
	if escrow.Tokens.Cmp(&params.MinDelegationAmount) < 0 {
		return staking.ErrInvalidArgument
	}

	id := ctx.TxSigner()
	from := state.Account(id)

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

	// Commit accounts.
	state.SetAccount(id, from)
	if !id.Equal(escrow.Account) {
		state.SetAccount(escrow.Account, to)
	}
	// Commit delegation descriptor.
	state.SetDelegation(id, escrow.Account, delegation)

	app.logger.Debug("AddEscrow: escrowed tokens",
		"from", id,
		"to", escrow.Account,
		"amount", escrow.Tokens,
	)

	evt := &staking.AddEscrowEvent{
		Owner:  id,
		Escrow: escrow.Account,
		Tokens: escrow.Tokens,
	}
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyAddEscrow, cbor.Marshal(evt)))

	return nil
}

func (app *stakingApplication) reclaimEscrow(ctx *abci.Context, state *stakingState.MutableState, reclaim *staking.ReclaimEscrow) error {
	// No sense if there is nothing to reclaim.
	if reclaim.Shares.IsZero() {
		return staking.ErrInvalidArgument
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpReclaimEscrow, params.GasCosts); err != nil {
		return err
	}

	id := ctx.TxSigner()
	to := state.Account(id)

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
	epoch, err := app.state.GetEpoch(ctx.Ctx(), ctx.BlockHeight()+1)
	if err != nil {
		return err
	}

	deb := staking.DebondingDelegation{
		DebondEndTime: epoch + debondingInterval,
	}

	var tokens quantity.Quantity

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

	state.SetDelegation(id, reclaim.Account, delegation)
	state.SetAccount(id, to)
	if !id.Equal(reclaim.Account) {
		state.SetAccount(reclaim.Account, from)
	}

	return nil
}

func (app *stakingApplication) amendCommissionSchedule(
	ctx *abci.Context,
	state *stakingState.MutableState,
	amendCommissionSchedule *staking.AmendCommissionSchedule,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpAmendCommissionSchedule, params.GasCosts); err != nil {
		return err
	}

	epoch, err := app.state.GetEpoch(ctx.Ctx(), ctx.BlockHeight()+1)
	if err != nil {
		return err
	}

	id := ctx.TxSigner()
	from := state.Account(id)

	if err = from.Escrow.CommissionSchedule.AmendAndPruneAndValidate(&amendCommissionSchedule.Amendment, &params.CommissionScheduleRules, epoch); err != nil {
		app.logger.Error("AmendCommissionSchedule: amendment not acceptable",
			"err", err,
			"from", id,
		)
		return err
	}

	state.SetAccount(id, from)

	return nil
}
