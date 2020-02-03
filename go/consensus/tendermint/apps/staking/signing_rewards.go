package staking

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

func (app *stakingApplication) updateEpochSigning(ctx *abci.Context, stakeState *stakingState.MutableState, signingEntities []signature.PublicKey) error {
	epochSigning, err := stakeState.EpochSigning()
	if err != nil {
		return fmt.Errorf("loading epoch signing info: %w", err)
	}

	if err := epochSigning.Update(signingEntities); err != nil {
		return err
	}

	stakeState.SetEpochSigning(epochSigning)

	return nil
}

func (app *stakingApplication) rewardEpochSigning(ctx *abci.Context, time epochtime.EpochTime) error {
	stakeState := stakingState.NewMutableState(ctx.State())

	params, err := stakeState.ConsensusParameters()
	if err != nil {
		return fmt.Errorf("loading consensus parameters: %w", err)
	}
	if params.SigningRewardThresholdDenominator == 0 {
		stakeState.ClearEpochSigning()
		return nil
	}

	epochSigning, err := stakeState.EpochSigning()
	if err != nil {
		return fmt.Errorf("loading epoch signing info: %w", err)
	}

	stakeState.ClearEpochSigning()

	if epochSigning.Total == 0 {
		return nil
	}

	eligibleEntities, err := epochSigning.EligibleEntities(params.SigningRewardThresholdNumerator, params.SigningRewardThresholdDenominator)
	if err != nil {
		return fmt.Errorf("determining eligibility: %w", err)
	}

	if err := stakeState.AddRewards(time, &params.RewardFactorEpochSigned, eligibleEntities); err != nil {
		return fmt.Errorf("adding rewards: %w", err)
	}

	return nil
}
