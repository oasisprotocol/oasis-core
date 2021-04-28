package staking

import (
	"context"
	"fmt"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var _ api.TransactionAuthHandler = (*stakingApplication)(nil)

// Implements api.TransactionAuthHandler.
func (app *stakingApplication) GetSignerNonce(ctx context.Context, req *consensus.GetSignerNonceRequest) (uint64, error) {
	q, err := app.QueryFactory().(*QueryFactory).QueryAt(ctx, req.Height)
	if err != nil {
		return 0, err
	}

	acct, err := q.Account(ctx, req.AccountAddress)
	if err != nil {
		return 0, err
	}
	return acct.General.Nonce, nil
}

// Implements api.TransactionAuthHandler.
func (app *stakingApplication) AuthenticateTx(ctx *api.Context, tx *transaction.Transaction) error {
	return stakingState.AuthenticateAndPayFees(ctx, ctx.TxSigner(), tx.Nonce, tx.Fee)
}

// Implements api.TransactionAuthHandler.
func (app *stakingApplication) PostExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	if !ctx.IsCheckOnly() {
		// Do not do anything outside CheckTx.
		return nil
	}

	// The below fee and nonce updates are performed for CheckTx in case all other transaction
	// checks passed and the transaction is ready to be included in the mempool. This should not be
	// done earlier (e.g. in AuthenticateTx) as that could increment the nonce even for otherwise
	// invalid transactions which will not be kept in the mempool (and so may be retried).
	state := stakingState.NewMutableState(ctx.State())

	fee := tx.Fee
	if fee == nil {
		fee = &transaction.Fee{}
	}

	addr := staking.NewAddress(ctx.TxSigner())

	account, err := state.Account(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to fetch account state: %w", err)
	}

	// Deduct fee and increment the nonce.
	if err := account.General.Balance.Sub(&fee.Amount); err != nil {
		return transaction.ErrInsufficientFeeBalance
	}

	account.General.Nonce++
	if err := state.SetAccount(ctx, addr, account); err != nil {
		return fmt.Errorf("failed to set account: %w", err)
	}

	return nil
}
