package state

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/consensus/gas"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

// AuthenticateAndPayFees authenticates the message signer and makes sure that
// any gas fees are paid.
//
// This method transfers the fees to the per-block fee accumulator which is
// persisted at the end of the block.
//
// When executed in a CheckTx context, this method returns a nil account as
// the caller should not do any further processing.
func AuthenticateAndPayFees(
	ctx *abci.Context,
	state *MutableState,
	id signature.PublicKey,
	nonce uint64,
	fee *gas.Fee,
) (*staking.Account, error) {
	// Fetch account and make sure the nonce is correct.
	account := state.Account(id)
	if account.General.Nonce != nonce {
		logger.Error("invalid account nonce",
			"account_id", id,
			"account_nonce", account.General.Nonce,
			"nonce", nonce,
		)
		return nil, staking.ErrInvalidNonce
	}

	if ctx.IsCheckOnly() {
		// Check that there is enough balance to pay fees. For the non-CheckTx case
		// this happens during Move below.
		if account.General.Balance.Cmp(&fee.Amount) < 0 {
			return nil, gas.ErrInsufficientFeeBalance
		}

		// Check fee against minimum gas price if in CheckTx.
		// NOTE: This is non-deterministic as it is derived from the local validator
		//       configuration, but as long as it is only done in CheckTx, this is ok.
		callerGasPrice := fee.GasPrice()
		if callerGasPrice.Cmp(ctx.AppState().MinGasPrice()) < 0 {
			return nil, gas.ErrGasPriceTooLow
		}

		return nil, nil
	}

	// Transfer fee to common pool.
	commonPool, err := state.CommonPool()
	if err != nil {
		return nil, fmt.Errorf("staking: failed to query common pool: %w", err)
	}
	if err = quantity.Move(commonPool, &account.General.Balance, &fee.Amount); err != nil {
		return nil, fmt.Errorf("staking: failed to pay fees: %w", err)
	}

	account.General.Nonce++
	state.SetCommonPool(commonPool)
	state.SetAccount(id, account)

	// Configure gas accountant on the context.
	ctx.SetGasAccountant(abci.NewGasAccountant(fee.Gas))

	return account, nil
}
