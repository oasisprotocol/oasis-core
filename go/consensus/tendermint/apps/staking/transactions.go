package staking

import (
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func (app *stakingApplication) transfer(ctx *abci.Context, state *stakingState.MutableState, signedXfer *staking.SignedTransfer) error {
	var xfer staking.Transfer
	if err := signedXfer.Open(staking.TransferSignatureContext, &xfer); err != nil {
		app.logger.Error("Transfer: invalid signature",
			"signed_xfer", signedXfer,
		)
		return staking.ErrInvalidSignature
	}

	// Authenticate sender and make sure fees are paid.
	fromID := signedXfer.Signature.PublicKey
	from, err := stakingState.AuthenticateAndPayFees(ctx, state, fromID, xfer.Nonce, &xfer.Fee)
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err := ctx.Gas().UseGas(staking.GasOpTransfer, params.GasCosts); err != nil {
		return err
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

func (app *stakingApplication) burn(ctx *abci.Context, state *stakingState.MutableState, signedBurn *staking.SignedBurn) error {
	var burn staking.Burn
	if err := signedBurn.Open(staking.BurnSignatureContext, &burn); err != nil {
		app.logger.Error("Burn: invalid signature",
			"signed_burn", signedBurn,
		)
		return staking.ErrInvalidSignature
	}

	// Authenticate sender and make sure fees are paid.
	id := signedBurn.Signature.PublicKey
	from, err := stakingState.AuthenticateAndPayFees(ctx, state, id, burn.Nonce, &burn.Fee)
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err := ctx.Gas().UseGas(staking.GasOpBurn, params.GasCosts); err != nil {
		return err
	}

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

func (app *stakingApplication) addEscrow(ctx *abci.Context, state *stakingState.MutableState, signedEscrow *staking.SignedEscrow) error {
	var escrow staking.Escrow
	if err := signedEscrow.Open(staking.EscrowSignatureContext, &escrow); err != nil {
		app.logger.Error("AddEscrow: invalid signature",
			"signed_escrow", signedEscrow,
		)
		return staking.ErrInvalidSignature
	}

	// Authenticate sender and make sure fees are paid.
	id := signedEscrow.Signature.PublicKey
	from, err := stakingState.AuthenticateAndPayFees(ctx, state, id, escrow.Nonce, &escrow.Fee)
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err := ctx.Gas().UseGas(staking.GasOpAddEscrow, params.GasCosts); err != nil {
		return err
	}

	// Check if sender provided at least a minimum amount of tokens.
	if escrow.Tokens.Cmp(&params.MinDelegationAmount) < 0 {
		return staking.ErrInvalidArgument
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

	evt := &staking.EscrowEvent{
		Owner:  id,
		Escrow: escrow.Account,
		Tokens: escrow.Tokens,
	}
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyAddEscrow, cbor.Marshal(evt)))

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

	// Authenticate sender and make sure fees are paid.
	id := signedReclaim.Signature.PublicKey
	to, err := stakingState.AuthenticateAndPayFees(ctx, state, id, reclaim.Nonce, &reclaim.Fee)
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(staking.GasOpReclaimEscrow, params.GasCosts); err != nil {
		return err
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

func (app *stakingApplication) amendCommissionSchedule(ctx *abci.Context, state *stakingState.MutableState, signedAmendCommissionSchedule *staking.SignedAmendCommissionSchedule) error {
	var amendCommissionSchedule staking.AmendCommissionSchedule
	if err := signedAmendCommissionSchedule.Open(staking.AmendCommissionScheduleSignatureContext, &amendCommissionSchedule); err != nil {
		app.logger.Error("ReclaimEscrow: invalid signature",
			"signed_amend_commission_schedule", signedAmendCommissionSchedule,
		)
		return staking.ErrInvalidSignature
	}

	// Authenticate sender and make sure fees are paid.
	id := signedAmendCommissionSchedule.Signature.PublicKey
	from, err := stakingState.AuthenticateAndPayFees(ctx, state, id, amendCommissionSchedule.Nonce, &amendCommissionSchedule.Fee)
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(staking.GasOpAmendCommissionSchedule, params.GasCosts); err != nil {
		return err
	}

	commit := true
	defer func() {
		if commit {
			state.SetAccount(id, from)
		}
	}()

	epoch, err := app.state.GetEpoch(ctx.Ctx(), ctx.BlockHeight()+1)
	if err != nil {
		return err
	}

	if err = from.Escrow.CommissionSchedule.AmendAndPruneAndValidate(&amendCommissionSchedule.Amendment, epoch, params.CommissionRateChangeInterval, params.CommissionRateBoundLead); err != nil {
		app.logger.Error("AmendCommissionSchedule: amendment not acceptable",
			"err", err,
			"from", id,
		)
		commit = false
	}

	return nil
}
