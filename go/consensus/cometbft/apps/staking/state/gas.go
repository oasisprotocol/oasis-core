package state

import (
	"fmt"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
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
	ctx *abciAPI.Context,
	signer signature.PublicKey,
	nonce uint64,
	fee *transaction.Fee,
) error {
	state := NewMutableState(ctx.State())

	if ctx.IsSimulation() {
		// If this is a simulation, the caller can use any amount of gas (as we usually want to
		// estimate the amount of gas needed).
		ctx.SetGasAccountant(abciAPI.NewGasAccountant(transaction.Gas(math.MaxUint64)))

		return nil
	}

	// Convert signer's public key to account address.
	addr := staking.NewAddress(signer)
	if addr.IsReserved() {
		return fmt.Errorf("using reserved account address %s is prohibited", addr)
	}

	// Fetch account and make sure the nonce is correct.
	account, err := state.Account(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to fetch account state: %w", err)
	}
	if account.General.Nonce != nonce {
		logger.Error("invalid account nonce",
			"account_addr", addr,
			"account_nonce", account.General.Nonce,
			"nonce", nonce,
		)
		return transaction.ErrInvalidNonce
	}

	if fee == nil {
		fee = &transaction.Fee{}
	}

	// Account must have enough to pay fee and maintain minimum balance.
	needed := fee.Amount.Clone()
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch staking consensus parameters: %w", err)
	}
	if err = needed.Add(&params.MinTransactBalance); err != nil {
		return fmt.Errorf("adding MinTransactBalance to fee: %w", err)
	}

	// Check against minimum balance plus fee.
	if account.General.Balance.Cmp(needed) < 0 {
		logger.Error("account balance too low",
			"account_addr", addr,
			"account_balance", account.General.Balance,
			"min_transact_balance", params.MinTransactBalance,
			"fee_amount", fee.Amount,
		)
		return staking.ErrBalanceTooLow
	}

	if ctx.IsCheckOnly() {
		// Configure gas accountant on the context so that we can report gas wanted.
		ctx.SetGasAccountant(abciAPI.NewGasAccountant(fee.Gas))

		// Check fee against minimum gas price if in CheckTx. Always accept own transactions.
		// NOTE: This is non-deterministic as it is derived from the local validator
		//       configuration, but as long as it is only done in CheckTx, this is ok.
		if !ctx.AppState().OwnTxSignerAddress().Equal(addr) {
			callerGasPrice := fee.GasPrice()
			if fee.Gas > 0 && callerGasPrice.Cmp(ctx.AppState().MinGasPrice()) < 0 {
				return transaction.ErrGasPriceTooLow
			}
		}

		return nil
	}

	// Transfer fee to per-block fee accumulator.
	feeAcc := ctx.BlockContext().Get(feeAccumulatorKey{}).(*feeAccumulator)
	if err = quantity.Move(&feeAcc.balance, &account.General.Balance, &fee.Amount); err != nil {
		return fmt.Errorf("staking: failed to pay fees: %w", err)
	}

	account.General.Nonce++
	if err := state.SetAccount(ctx, addr, account); err != nil {
		return fmt.Errorf("failed to set account: %w", err)
	}

	// Emit transfer event if fee is non-zero.
	if !fee.Amount.IsZero() {
		ctx.EmitEvent(abciAPI.NewEventBuilder(AppName).TypedAttribute(&staking.TransferEvent{
			From:   addr,
			To:     staking.FeeAccumulatorAddress,
			Amount: fee.Amount,
		}))
	}

	// Configure gas accountant on the context.
	ctx.SetGasAccountant(abciAPI.NewCompositeGasAccountant(
		abciAPI.NewGasAccountant(fee.Gas),
		ctx.BlockContext().GasAccountant,
	))

	return nil
}

// BlockFees returns the accumulated fee balance for the current block.
func BlockFees(ctx *abciAPI.Context) quantity.Quantity {
	// Fetch accumulated fees in the current block.
	return ctx.BlockContext().Get(feeAccumulatorKey{}).(*feeAccumulator).balance
}

// proposerKey is the block context key.
type proposerKey struct{}

func (pk proposerKey) NewDefault() interface{} {
	var empty *signature.PublicKey
	return empty
}

func SetBlockProposer(ctx *abciAPI.Context, p *signature.PublicKey) {
	ctx.BlockContext().Set(proposerKey{}, p)
}

func BlockProposer(ctx *abciAPI.Context) *signature.PublicKey {
	return ctx.BlockContext().Get(proposerKey{}).(*signature.PublicKey)
}
