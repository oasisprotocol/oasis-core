package staking

import (
	"context"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
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
