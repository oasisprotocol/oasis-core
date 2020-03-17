package staking

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
)

// disburseFeesP disburses fees to the proposer.
//
// In case of errors the state may be inconsistent.
func (app *stakingApplication) disburseFeesP(ctx *abci.Context, stakeState *stakingState.MutableState, proposerEntity *signature.PublicKey, totalFees *quantity.Quantity) error {
	ctx.Logger().Debug("disbursing proposer fees",
		"total_amount", totalFees,
	)
	if totalFees.IsZero() {
		stakeState.SetLastBlockFees(totalFees)
		return nil
	}

	consensusParameters, err := stakeState.ConsensusParameters()
	if err != nil {
		return fmt.Errorf("ConsensusParameters: %w", err)
	}

	numPersist := consensusParameters.FeeSplitWeightVote.Clone()
	if err = numPersist.Add(&consensusParameters.FeeSplitWeightNextPropose); err != nil {
		return fmt.Errorf("add FeeSplitWeightNextPropose: %w", err)
	}
	denom := numPersist.Clone()
	if err = denom.Add(&consensusParameters.FeeSplitWeightPropose); err != nil {
		return fmt.Errorf("add FeeSplitWeightPropose: %w", err)
	}
	feePersistAmt := totalFees.Clone()
	if err = feePersistAmt.Mul(numPersist); err != nil {
		return fmt.Errorf("multiply feePersistAmt: %w", err)
	}
	if feePersistAmt.Quo(denom) != nil {
		return fmt.Errorf("divide feePersistAmt: %w", err)
	}

	feePersist := quantity.NewQuantity()
	if err = quantity.Move(feePersist, totalFees, feePersistAmt); err != nil {
		return fmt.Errorf("move feePersist: %w", err)
	}
	stakeState.SetLastBlockFees(feePersist)

	feeProposerAmt := totalFees.Clone()
	if proposerEntity != nil {
		acct := stakeState.Account(*proposerEntity)
		if err = quantity.Move(&acct.General.Balance, totalFees, feeProposerAmt); err != nil {
			return fmt.Errorf("move feeProposerAmt: %w", err)
		}
		stakeState.SetAccount(*proposerEntity, acct)
	}

	if !totalFees.IsZero() {
		remaining := totalFees.Clone()
		commonPool, err := stakeState.CommonPool()
		if err != nil {
			return fmt.Errorf("CommonPool: %w", err)
		}
		if err = quantity.Move(commonPool, totalFees, remaining); err != nil {
			return fmt.Errorf("move remaining: %w", err)
		}
		stakeState.SetCommonPool(commonPool)
	}

	return nil
}

// disburseFeesVQ disburses fees to the voters and next proposer.
//
// In case of errors the state may be inconsistent.
func (app *stakingApplication) disburseFeesVQ(ctx *abci.Context, stakeState *stakingState.MutableState, proposerEntity *signature.PublicKey, numEligibleValidators int, votingEntities []signature.PublicKey) error {
	lastBlockFees, err := stakeState.LastBlockFees()
	if err != nil {
		return fmt.Errorf("staking: failed to query last block fees: %w", err)
	}

	ctx.Logger().Debug("disbursing signer and next proposer fees",
		"total_amount", lastBlockFees,
		"num_eligible_validators", numEligibleValidators,
		"num_voting_entities", len(votingEntities),
	)
	if lastBlockFees.IsZero() {
		// Nothing to disburse.
		return nil
	}

	consensusParameters, err := stakeState.ConsensusParameters()
	if err != nil {
		return fmt.Errorf("ConsensusParameters: %w", err)
	}

	denom := consensusParameters.FeeSplitWeightVote.Clone()
	if err = denom.Add(&consensusParameters.FeeSplitWeightNextPropose); err != nil {
		return fmt.Errorf("add FeeSplitWeightNextPropose: %w", err)
	}
	perValidator := lastBlockFees.Clone()
	var nEVQ quantity.Quantity
	if err = nEVQ.FromInt64(int64(numEligibleValidators)); err != nil {
		return fmt.Errorf("import numEligibleValidators %d: %w", numEligibleValidators, err)
	}
	if err = perValidator.Quo(&nEVQ); err != nil {
		return fmt.Errorf("divide perValidator: %w", err)
	}
	shareNextProposer := perValidator.Clone()
	if err = shareNextProposer.Mul(&consensusParameters.FeeSplitWeightNextPropose); err != nil {
		return fmt.Errorf("multiply shareNextProposer: %w", err)
	}
	if err = shareNextProposer.Quo(denom); err != nil {
		return fmt.Errorf("divide shareNextProposer: %w", err)
	}
	shareVote := perValidator.Clone()
	if err = shareVote.Sub(shareNextProposer); err != nil {
		return fmt.Errorf("subtract shareVote: %w", err)
	}

	numVotingEntities := len(votingEntities)
	var nVEQ quantity.Quantity
	if err = nVEQ.FromInt64(int64(numVotingEntities)); err != nil {
		return fmt.Errorf("import numVotingEntities %d: %w", numVotingEntities, err)
	}
	nextProposerTotal := shareNextProposer.Clone()
	if err = nextProposerTotal.Mul(&nVEQ); err != nil {
		return fmt.Errorf("multiply nextProposerTotal: %w", err)
	}

	if !nextProposerTotal.IsZero() {
		if proposerEntity != nil {
			acct := stakeState.Account(*proposerEntity)
			if err = quantity.Move(&acct.General.Balance, lastBlockFees, nextProposerTotal); err != nil {
				return fmt.Errorf("move nextProposerTotal: %w", err)
			}
			stakeState.SetAccount(*proposerEntity, acct)
		}
	}

	if !shareVote.IsZero() {
		for _, voterEntity := range votingEntities {
			acct := stakeState.Account(voterEntity)
			if err = quantity.Move(&acct.General.Balance, lastBlockFees, shareVote); err != nil {
				return fmt.Errorf("move shareVote: %w", err)
			}
			stakeState.SetAccount(voterEntity, acct)
		}
	}

	if !lastBlockFees.IsZero() {
		remaining := lastBlockFees.Clone()
		commonPool, err := stakeState.CommonPool()
		if err != nil {
			return fmt.Errorf("CommonPool: %w", err)
		}
		if err = quantity.Move(commonPool, lastBlockFees, remaining); err != nil {
			return fmt.Errorf("move remaining: %w", err)
		}
		stakeState.SetCommonPool(commonPool)
	}

	return nil
}
