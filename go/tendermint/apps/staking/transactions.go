package staking

import (
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
	stakingState "github.com/oasislabs/oasis-core/go/tendermint/apps/staking/state"
)

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

	to.General.Nonce++
	state.SetDelegation(id, reclaim.Account, delegation)
	state.SetAccount(id, to)
	if !id.Equal(reclaim.Account) {
		state.SetAccount(reclaim.Account, from)
	}

	return nil
}
