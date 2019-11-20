package state

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
)

// feeAccumulatorKey is the block context key.
type feeAccumulatorKey struct{}

func (fak feeAccumulatorKey) NewDefault() interface{} {
	return &feeAccumulator{}
}

// feeAccumulator is the per-block fee accumulator that gets all fees paid
// in a block.
type feeAccumulator struct {
	balance quantity.Quantity
}

// AuthenticateAndPayFees authenticates the message signer and makes sure that
// any gas fees are paid.
//
// This method transfers the fees to the per-block fee accumulator which is
// persisted at the end of the block.
func AuthenticateAndPayFees(
	ctx *abci.Context,
	id signature.PublicKey,
	nonce uint64,
	fee *transaction.Fee,
) error {
	state := NewMutableState(ctx.State())

	// Fetch account and make sure the nonce is correct.
	account := state.Account(id)
	if account.General.Nonce != nonce {
		logger.Error("invalid account nonce",
			"account_id", id,
			"account_nonce", account.General.Nonce,
			"nonce", nonce,
		)
		return transaction.ErrInvalidNonce
	}

	if fee == nil {
		fee = &transaction.Fee{}
	}

	if ctx.IsCheckOnly() {
		// Configure gas accountant on the context so that we can report gas wanted.
		ctx.SetGasAccountant(abci.NewGasAccountant(fee.Gas))

		// Check that there is enough balance to pay fees. For the non-CheckTx case
		// this happens during Move below.
		if account.General.Balance.Cmp(&fee.Amount) < 0 {
			return transaction.ErrInsufficientFeeBalance
		}

		// Check fee against minimum gas price if in CheckTx.
		// NOTE: This is non-deterministic as it is derived from the local validator
		//       configuration, but as long as it is only done in CheckTx, this is ok.
		callerGasPrice := fee.GasPrice()
		if fee.Gas > 0 && callerGasPrice.Cmp(ctx.AppState().MinGasPrice()) < 0 {
			return transaction.ErrGasPriceTooLow
		}

		return nil
	}

	// Transfer fee to per-block fee accumulator.
	feeAcc := ctx.BlockContext().Get(feeAccumulatorKey{}).(*feeAccumulator)
	if err := quantity.Move(&feeAcc.balance, &account.General.Balance, &fee.Amount); err != nil {
		return fmt.Errorf("staking: failed to pay fees: %w", err)
	}

	account.General.Nonce++
	state.SetAccount(id, account)

	// Configure gas accountant on the context.
	ctx.SetGasAccountant(abci.NewCompositeGasAccountant(
		abci.NewGasAccountant(fee.Gas),
		ctx.BlockContext().Get(abci.GasAccountantKey{}).(abci.GasAccountant),
	))

	return nil
}

// PersistBlockFees persists the accumulated fee balance for the current block.
func PersistBlockFees(ctx *abci.Context) {
	// Fetch accumulated fees in the current block.
	fees := ctx.BlockContext().Get(feeAccumulatorKey{}).(*feeAccumulator).balance

	state := NewMutableState(ctx.State())
	state.SetLastBlockFees(&fees)
}
