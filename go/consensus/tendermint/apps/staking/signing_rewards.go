package staking

import (
	"bytes"
	"fmt"
	"math"
	"sort"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func (app *stakingApplication) updateEpochSigning(ctx *abci.Context, signingEntities []signature.PublicKey) error {
	stakeState := stakingState.NewMutableState(ctx.State())

	epochSigning, err := stakeState.EpochSigning()
	if err != nil {
		return fmt.Errorf("loading epoch signing info: %w", err)
	}

	oldTotal := epochSigning.Total
	epochSigning.Total = oldTotal + 1
	if epochSigning.Total <= oldTotal {
		return fmt.Errorf("incrementing total blocks count: overflow, old_total=%d", oldTotal)
	}

	for _, entityID := range signingEntities {
		oldCount := epochSigning.ByEntity[entityID]
		epochSigning.ByEntity[entityID] = oldCount + 1
		if epochSigning.ByEntity[entityID] <= oldCount {
			return fmt.Errorf("incrementing count for entity %s: overflow, old_count=%d", entityID, oldCount)
		}
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

	var eligibleEntities []signature.PublicKey
	if epochSigning.Total > math.MaxUint64/params.SigningRewardThresholdNumerator {
		return fmt.Errorf("determining eligibility: overflow in total blocks, total=%d", epochSigning.Total)
	}
	for entityID, count := range epochSigning.ByEntity {
		if count > math.MaxUint64/params.SigningRewardThresholdDenominator {
			return fmt.Errorf("determining eligibility for entity %s: overflow in threshold comparison, count=%d", entityID, count)
		}
		if count*params.SigningRewardThresholdDenominator < epochSigning.Total*params.SigningRewardThresholdNumerator {
			continue
		}
		eligibleEntities = append(eligibleEntities, entityID)
	}
	sort.Slice(eligibleEntities, func(i, j int) bool {
		return bytes.Compare(eligibleEntities[i][:], eligibleEntities[j][:]) < 0
	})

	if err := stakeState.AddRewards(time, staking.RewardFactorEpochSigned, eligibleEntities); err != nil {
		return fmt.Errorf("adding rewards: %w", err)
	}

	return nil
}
