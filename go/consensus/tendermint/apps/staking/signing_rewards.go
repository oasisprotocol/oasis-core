package staking

import (
	"fmt"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *stakingApplication) updateEpochSigning(
	ctx *abciAPI.Context,
	stakeState *stakingState.MutableState,
	signingAddresses []staking.Address,
) error {
	epochSigning, err := stakeState.EpochSigning(ctx)
	if err != nil {
		return fmt.Errorf("loading epoch signing info: %w", err)
	}

	if err := epochSigning.Update(signingAddresses); err != nil {
		return err
	}

	if err := stakeState.SetEpochSigning(ctx, epochSigning); err != nil {
		return fmt.Errorf("failed to set epoch signing info: %w", err)
	}

	return nil
}

func (app *stakingApplication) rewardEpochSigning(ctx *abciAPI.Context, time epochtime.EpochTime) error {
	stakeState := stakingState.NewMutableState(ctx.State())

	params, err := stakeState.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("loading consensus parameters: %w", err)
	}
	if params.SigningRewardThresholdDenominator == 0 {
		if err = stakeState.ClearEpochSigning(ctx); err != nil {
			return fmt.Errorf("failed to clear epoch signing: %w", err)
		}
		return nil
	}

	epochSigning, err := stakeState.EpochSigning(ctx)
	if err != nil {
		return fmt.Errorf("loading epoch signing info: %w", err)
	}

	if err = stakeState.ClearEpochSigning(ctx); err != nil {
		return fmt.Errorf("failed to clear epoch signing: %w", err)
	}

	if epochSigning.Total == 0 {
		return nil
	}

	eligibleAddresses, err := epochSigning.EligibleAddresses(
		params.SigningRewardThresholdNumerator,
		params.SigningRewardThresholdDenominator,
	)
	if err != nil {
		return fmt.Errorf("determining eligibility: %w", err)
	}

	if err := stakeState.AddRewards(ctx, time, &params.RewardFactorEpochSigned, eligibleAddresses); err != nil {
		return fmt.Errorf("adding rewards: %w", err)
	}

	return nil
}
