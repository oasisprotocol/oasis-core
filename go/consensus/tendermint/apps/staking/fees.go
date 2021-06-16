package staking

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// disburseFeesP disburses fees to the proposer and persists the voters' and next proposer's shares of the fees.
//
// In case of errors the state may be inconsistent.
func (app *stakingApplication) disburseFeesP(
	ctx *abciAPI.Context,
	stakeState *stakingState.MutableState,
	proposerEntity *signature.PublicKey,
	totalFees *quantity.Quantity,
) error {
	ctx.Logger().Debug("disbursing proposer fees",
		"total_amount", totalFees,
	)
	if totalFees.IsZero() {
		if err := stakeState.SetLastBlockFees(ctx, totalFees); err != nil {
			return fmt.Errorf("failed to set last block fees: %w", err)
		}
		return nil
	}

	consensusParameters, err := stakeState.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("ConsensusParameters: %w", err)
	}

	// Compute how much to persist for voters and the next proposer.
	weightVQ := consensusParameters.FeeSplitWeightVote.Clone()
	if err = weightVQ.Add(&consensusParameters.FeeSplitWeightNextPropose); err != nil {
		return fmt.Errorf("add FeeSplitWeightNextPropose: %w", err)
	}
	weightPVQ := weightVQ.Clone()
	if err = weightPVQ.Add(&consensusParameters.FeeSplitWeightPropose); err != nil {
		return fmt.Errorf("add FeeSplitWeightPropose: %w", err)
	}
	feePersistAmt := totalFees.Clone()
	if err = feePersistAmt.Mul(weightVQ); err != nil {
		return fmt.Errorf("multiply feePersistAmt: %w", err)
	}
	if feePersistAmt.Quo(weightPVQ) != nil {
		return fmt.Errorf("divide feePersistAmt: %w", err)
	}

	// Persist voters' and next proposer's shares of the fees.
	feePersist := quantity.NewQuantity()
	if err = quantity.Move(feePersist, totalFees, feePersistAmt); err != nil {
		return fmt.Errorf("move feePersist: %w", err)
	}
	if err = stakeState.SetLastBlockFees(ctx, feePersist); err != nil {
		return fmt.Errorf("failed to set last block fees: %w", err)
	}

	// Pay the proposer.
	feeProposerAmt := totalFees.Clone()
	if proposerEntity != nil && !feeProposerAmt.IsZero() {
		proposerAddr := staking.NewAddress(*proposerEntity)
		proposerAcct, err := stakeState.Account(ctx, proposerAddr)
		if err != nil {
			return fmt.Errorf("failed to fetch proposer account: %w", err)
		}
		if err = quantity.Move(&proposerAcct.General.Balance, totalFees, feeProposerAmt); err != nil {
			return fmt.Errorf("move feeProposerAmt: %w", err)
		}
		if err = stakeState.SetAccount(ctx, proposerAddr, proposerAcct); err != nil {
			return fmt.Errorf("failed to set account: %w", err)
		}

		// Emit transfer event.
		ctx.EmitEvent(abciAPI.NewEventBuilder(app.Name()).TypedAttribute(&staking.TransferEvent{
			From:   staking.FeeAccumulatorAddress,
			To:     proposerAddr,
			Amount: *feeProposerAmt,
		}))
	}

	// Put the rest into the common pool (in case there is no proposer entity to pay).
	if !totalFees.IsZero() {
		remaining := totalFees.Clone()
		commonPool, err := stakeState.CommonPool(ctx)
		if err != nil {
			return fmt.Errorf("CommonPool: %w", err)
		}
		if err = quantity.Move(commonPool, totalFees, remaining); err != nil {
			return fmt.Errorf("move remaining: %w", err)
		}
		if err = stakeState.SetCommonPool(ctx, commonPool); err != nil {
			return fmt.Errorf("failed to set common pool: %w", err)
		}

		// Emit transfer event.
		ctx.EmitEvent(abciAPI.NewEventBuilder(app.Name()).TypedAttribute(&staking.TransferEvent{
			From:   staking.FeeAccumulatorAddress,
			To:     staking.CommonPoolAddress,
			Amount: *remaining,
		}))
	}

	return nil
}

// disburseFeesVQ disburses persisted fees to the voters and next proposer.
//
// In case of errors the state may be inconsistent.
func (app *stakingApplication) disburseFeesVQ(
	ctx *abciAPI.Context,
	stakeState *stakingState.MutableState,
	proposerEntity *signature.PublicKey,
	numEligibleValidators int,
	votingEntities []signature.PublicKey,
) error {
	lastBlockFees, err := stakeState.LastBlockFees(ctx)
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

	consensusParameters, err := stakeState.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("ConsensusParameters: %w", err)
	}

	// Compute the portion associated with each eligible validator's share of the fees, and within that, how much goes
	// to the voter and how much goes to the next proposer.
	perValidator := lastBlockFees.Clone()
	var nEVQ quantity.Quantity
	if err = nEVQ.FromInt64(int64(numEligibleValidators)); err != nil {
		return fmt.Errorf("import numEligibleValidators %d: %w", numEligibleValidators, err)
	}
	if err = perValidator.Quo(&nEVQ); err != nil {
		return fmt.Errorf("divide perValidator: %w", err)
	}
	denom := consensusParameters.FeeSplitWeightVote.Clone()
	if err = denom.Add(&consensusParameters.FeeSplitWeightNextPropose); err != nil {
		return fmt.Errorf("add FeeSplitWeightNextPropose: %w", err)
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

	// Multiply to get the next proposer's total payment.
	numVotingEntities := len(votingEntities)
	var nVEQ quantity.Quantity
	if err = nVEQ.FromInt64(int64(numVotingEntities)); err != nil {
		return fmt.Errorf("import numVotingEntities %d: %w", numVotingEntities, err)
	}
	nextProposerTotal := shareNextProposer.Clone()
	if err = nextProposerTotal.Mul(&nVEQ); err != nil {
		return fmt.Errorf("multiply nextProposerTotal: %w", err)
	}

	// Pay the next proposer.
	if !nextProposerTotal.IsZero() && proposerEntity != nil {
		proposerAddr := staking.NewAddress(*proposerEntity)
		proposerAcct, err := stakeState.Account(ctx, proposerAddr)
		if err != nil {
			return fmt.Errorf("failed to fetch next proposer account: %w", err)
		}
		if err = quantity.Move(&proposerAcct.General.Balance, lastBlockFees, nextProposerTotal); err != nil {
			return fmt.Errorf("move nextProposerTotal: %w", err)
		}
		if err = stakeState.SetAccount(ctx, proposerAddr, proposerAcct); err != nil {
			return fmt.Errorf("failed to set next proposer account: %w", err)
		}

		// Emit transfer event.
		ctx.EmitEvent(abciAPI.NewEventBuilder(app.Name()).TypedAttribute(&staking.TransferEvent{
			From:   staking.FeeAccumulatorAddress,
			To:     proposerAddr,
			Amount: *nextProposerTotal,
		}))
	}

	// Pay the voters.
	if !shareVote.IsZero() {
		for _, voterEntity := range votingEntities {
			voterAddr := staking.NewAddress(voterEntity)
			voterAcct, err := stakeState.Account(ctx, voterAddr)
			if err != nil {
				return fmt.Errorf("failed to fetch voter account %s: %w", voterAddr, err)
			}
			if err = quantity.Move(&voterAcct.General.Balance, lastBlockFees, shareVote); err != nil {
				return fmt.Errorf("move shareVote: %w", err)
			}
			if err = stakeState.SetAccount(ctx, voterAddr, voterAcct); err != nil {
				return fmt.Errorf("failed to set voter account %s: %w", voterAddr, err)
			}

			// Emit transfer event.
			ctx.EmitEvent(abciAPI.NewEventBuilder(app.Name()).TypedAttribute(&staking.TransferEvent{
				From:   staking.FeeAccumulatorAddress,
				To:     voterAddr,
				Amount: *shareVote,
			}))
		}
	}

	// Put the rest into the common pool.
	if !lastBlockFees.IsZero() {
		remaining := lastBlockFees.Clone()
		commonPool, err := stakeState.CommonPool(ctx)
		if err != nil {
			return fmt.Errorf("failed to query common pool: %w", err)
		}
		if err = quantity.Move(commonPool, lastBlockFees, remaining); err != nil {
			return fmt.Errorf("move remaining: %w", err)
		}
		if err = stakeState.SetCommonPool(ctx, commonPool); err != nil {
			return fmt.Errorf("failed to set common pool: %w", err)
		}

		// Emit transfer event.
		ctx.EmitEvent(abciAPI.NewEventBuilder(app.Name()).TypedAttribute(&staking.TransferEvent{
			From:   staking.FeeAccumulatorAddress,
			To:     staking.CommonPoolAddress,
			Amount: *remaining,
		}))
	}

	return nil
}
