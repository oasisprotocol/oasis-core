package staking

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
)

var _ abci.TransactionAuthHandler = (*stakingApplication)(nil)

// Implements abci.TransactionAuthHandler.
func (app *stakingApplication) GetSignerNonce(ctx context.Context, id signature.PublicKey, height int64) (uint64, error) {
	q, err := app.QueryFactory().(*QueryFactory).QueryAt(ctx, height)
	if err != nil {
		return 0, err
	}

	acct, err := q.AccountInfo(ctx, id)
	if err != nil {
		return 0, err
	}
	return acct.General.Nonce, nil
}

// Implements abci.TransactionAuthHandler.
func (app *stakingApplication) AuthenticateTx(ctx *abci.Context, tx *transaction.Transaction) error {
	epoch, err := app.state.GetCurrentEpoch(ctx.Ctx())
	if err != nil {
		return fmt.Errorf("getting current epoch: %w", err)
	}
	return stakingState.AuthenticateAndPayFees(ctx, ctx.TxSigner(), tx.Nonce, tx.Fee, epoch)
}
