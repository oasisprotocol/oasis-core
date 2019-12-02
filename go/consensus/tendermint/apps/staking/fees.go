package staking

import (
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
)

type disbursement struct {
	id     signature.PublicKey
	weight int64
}

// disburseFees disburses fees.
//
// In case of errors the state may be inconsistent.
func (app *stakingApplication) disburseFees(ctx *abci.Context, lastCommitInfo types.LastCommitInfo) error {
	stakeState := stakingState.NewMutableState(ctx.State())

	totalFees, err := stakeState.LastBlockFees()
	if err != nil {
		return fmt.Errorf("staking: failed to query last block fees: %w", err)
	}

	app.logger.Debug("disbursing fees",
		"total_amount", totalFees,
	)
	if totalFees.IsZero() {
		// Nothing to disburse.
		return nil
	}

	// Go through all signers of the previous block and resolve entities.
	signingEntities := app.resolveEntityIDsFromVotes(ctx, lastCommitInfo)

	var rewardAccounts []disbursement
	var totalWeight int64
	for _, entityID := range signingEntities {
		d := disbursement{
			id: entityID,
			// For now we just disburse equally.
			weight: 1,
		}
		rewardAccounts = append(rewardAccounts, d)
		totalWeight += d.weight
	}

	// Calculate the amount of fees to disburse.
	var totalWeightQ quantity.Quantity
	_ = totalWeightQ.FromInt64(totalWeight)

	feeShare := totalFees.Clone()
	if err := feeShare.Quo(&totalWeightQ); err != nil {
		return err
	}
	for _, d := range rewardAccounts {
		var weightQ quantity.Quantity
		_ = weightQ.FromInt64(d.weight)

		// Calculate how much to disburse to this account.
		disburseAmount := feeShare.Clone()
		if err := disburseAmount.Mul(&weightQ); err != nil {
			return fmt.Errorf("staking: failed to disburse fees: %w", err)
		}
		// Perform the transfer.
		acct := stakeState.Account(d.id)
		if err := quantity.Move(&acct.General.Balance, totalFees, disburseAmount); err != nil {
			app.logger.Error("failed to disburse fees",
				"err", err,
				"to", d.id,
				"amount", disburseAmount,
			)
			return fmt.Errorf("staking: failed to disburse fees: %w", err)
		}
		stakeState.SetAccount(d.id, acct)
	}
	// Any remainder goes to the common pool.
	if !totalFees.IsZero() {
		commonPool, err := stakeState.CommonPool()
		if err != nil {
			return fmt.Errorf("staking: failed to query common pool: %w", err)
		}
		if err := quantity.Move(commonPool, totalFees, totalFees); err != nil {
			app.logger.Error("failed to move remainder to common pool",
				"err", err,
				"amount", totalFees,
			)
			return fmt.Errorf("staking: failed to move to common pool: %w", err)
		}
		stakeState.SetCommonPool(commonPool)
	}

	return nil
}
