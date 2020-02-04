package staking

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
)

// disburseFees disburses fees.
//
// In case of errors the state may be inconsistent.
func (app *stakingApplication) disburseFees(ctx *abci.Context, stakeState *stakingState.MutableState, proposerEntity *signature.PublicKey, numEligibleVotes int, signingEntities []signature.PublicKey) error {
	totalFees, err := stakeState.LastBlockFees()
	if err != nil {
		return fmt.Errorf("staking: failed to query last block fees: %w", err)
	}

	ctx.Logger().Debug("disbursing fees",
		"total_amount", totalFees,
	)
	if totalFees.IsZero() {
		// Nothing to disburse.
		return nil
	}

	consensusParameters, err := stakeState.ConsensusParameters()
	if err != nil {
		return fmt.Errorf("staking: failed to load consensus parameters: %w", err)
	}

	denom := consensusParameters.FeeSplitVote.Clone()
	if err = denom.Add(&consensusParameters.FeeSplitPropose); err != nil {
		return fmt.Errorf("add fee splits: %w", err)
	}
	var nEVQ quantity.Quantity
	if err = nEVQ.FromInt64(int64(numEligibleVotes)); err != nil {
		return fmt.Errorf("import numEligibleVotes %d: %w", numEligibleVotes, err)
	}
	if err = denom.Mul(&nEVQ); err != nil {
		return fmt.Errorf("multiply denom: %w", err)
	}

	perVIVote := totalFees.Clone()
	if err = perVIVote.Mul(&consensusParameters.FeeSplitVote); err != nil {
		return fmt.Errorf("multiply perVIVote: %w", err)
	}
	if err = perVIVote.Quo(denom); err != nil {
		return fmt.Errorf("divide perVIVote: %w", err)
	}
	perVIPropose := totalFees.Clone()
	if err = perVIPropose.Mul(&consensusParameters.FeeSplitPropose); err != nil {
		return fmt.Errorf("multiply perVIPropose: %w", err)
	}
	// The per-VoteInfo proposer share is first rounded (down), then multiplied by the number of shares.
	// This keeps incentives from having nonuniform breakpoints at certain signature counts.
	if err = perVIPropose.Quo(denom); err != nil {
		return fmt.Errorf("divide perVIPropose: %w", err)
	}
	numSigningEntities := len(signingEntities)
	var nSEQ quantity.Quantity
	if err = nSEQ.FromInt64(int64(numSigningEntities)); err != nil {
		return fmt.Errorf("import numSigningEntities %d: %w", numSigningEntities, err)
	}
	proposeTotal := perVIPropose.Clone()
	if err = proposeTotal.Mul(&nSEQ); err != nil {
		return fmt.Errorf("multiply proposeTotal: %w", err)
	}

	// Pay proposer.
	if !proposeTotal.IsZero() {
		if proposerEntity != nil {
			// Perform the transfer.
			acct := stakeState.Account(*proposerEntity)
			if err = quantity.Move(&acct.General.Balance, totalFees, proposeTotal); err != nil {
				ctx.Logger().Error("failed to disburse fees (propose)",
					"err", err,
					"to", *proposerEntity,
					"amount", proposeTotal,
				)
				return fmt.Errorf("staking: failed to disburse fees (propose): %w", err)
			}
			stakeState.SetAccount(*proposerEntity, acct)
		}
	}
	// Pay voters.
	if !perVIVote.IsZero() {
		for _, voterEntity := range signingEntities {
			// Perform the transfer.
			acct := stakeState.Account(voterEntity)
			if err = quantity.Move(&acct.General.Balance, totalFees, perVIVote); err != nil {
				ctx.Logger().Error("failed to disburse fees (vote)",
					"err", err,
					"to", voterEntity,
					"amount", perVIVote,
				)
				return fmt.Errorf("staking: failed to disburse fees (vote): %w", err)
			}
			stakeState.SetAccount(voterEntity, acct)
		}
	}
	// Any remainder goes to the common pool.
	if !totalFees.IsZero() {
		commonPool, err := stakeState.CommonPool()
		if err != nil {
			return fmt.Errorf("staking: failed to query common pool: %w", err)
		}
		if err := quantity.Move(commonPool, totalFees, totalFees); err != nil {
			ctx.Logger().Error("failed to move remainder to common pool",
				"err", err,
				"amount", totalFees,
			)
			return fmt.Errorf("staking: failed to move to common pool: %w", err)
		}
		stakeState.SetCommonPool(commonPool)
	}

	return nil
}
