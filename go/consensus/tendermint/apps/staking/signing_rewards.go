package staking

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *stakingApplication) updateEpochSigning(
	ctx *abciAPI.Context,
	stakeState *stakingState.MutableState,
	signingEntities []signature.PublicKey,
) error {
	epochSigning, err := stakeState.EpochSigning(ctx)
	if err != nil {
		return fmt.Errorf("loading epoch signing info: %w", err)
	}

	if err := epochSigning.Update(signingEntities); err != nil {
		return err
	}

	if err := stakeState.SetEpochSigning(ctx, epochSigning); err != nil {
		return fmt.Errorf("failed to set epoch signing info: %w", err)
	}

	return nil
}

func (app *stakingApplication) rewardEpochSigning(ctx *abciAPI.Context, time beacon.EpochTime) error {
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

	eligibleEntities, err := epochSigning.EligibleEntities(
		params.SigningRewardThresholdNumerator,
		params.SigningRewardThresholdDenominator,
	)
	if err != nil {
		return fmt.Errorf("determining eligibility: %w", err)
	}
	var eligibleEntitiesAddrs []staking.Address
	for _, entity := range eligibleEntities {
		eligibleEntitiesAddrs = append(eligibleEntitiesAddrs, staking.NewAddress(entity))
	}

	if err := stakeState.AddRewards(ctx, time, &params.RewardFactorEpochSigned, eligibleEntitiesAddrs); err != nil {
		return fmt.Errorf("adding rewards: %w", err)
	}

	return nil
}
