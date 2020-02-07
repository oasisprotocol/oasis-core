package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/quantity"
)

func TestConsensusParameters(t *testing.T) {
	require := require.New(t)

	// Default consensus parameters.
	var emptyParams ConsensusParameters
	require.Error(emptyParams.SanityCheck(), "default consensus parameters should be invalid")

	// Valid thresholds.
	validThresholds := map[ThresholdKind]quantity.Quantity{
		KindEntity:            *quantity.NewQuantity(),
		KindValidator:         *quantity.NewQuantity(),
		KindCompute:           *quantity.NewQuantity(),
		KindStorage:           *quantity.NewQuantity(),
		KindRuntimeCompute:    *quantity.NewQuantity(),
		KindRuntimeKeyManager: *quantity.NewQuantity(),
	}
	validThresholdsParams := ConsensusParameters{
		Thresholds:   validThresholds,
		FeeSplitVote: mustInitQuantity(t, 1),
	}
	require.NoError(validThresholdsParams.SanityCheck(), "consensus parameters with valid thresholds should be valid")

	// NOTE: There is currently no way to construct invalid thresholds.

	// Degenerate fee split.
	degenerateFeeSplit := ConsensusParameters{
		Thresholds:      validThresholds,
		FeeSplitVote:    mustInitQuantity(t, 0),
		FeeSplitPropose: mustInitQuantity(t, 0),
	}
	require.Error(degenerateFeeSplit.SanityCheck(), "consensus parameters with degenerate fee split should be invalid")
}

func TestStakeAccumulator(t *testing.T) {
	require := require.New(t)

	thresholds := map[ThresholdKind]quantity.Quantity{
		KindEntity:            qtyFromInt(1_000),
		KindValidator:         qtyFromInt(10_000),
		KindCompute:           qtyFromInt(5_000),
		KindStorage:           qtyFromInt(2_000),
		KindRuntimeCompute:    qtyFromInt(100_000),
		KindRuntimeKeyManager: qtyFromInt(1_000_000),
	}

	// Empty escrow account tests.
	var acct EscrowAccount
	err := acct.CheckStakeClaims(thresholds)
	require.NoError(err, "empty escrow account should check out")
	err = acct.RemoveStakeClaim(StakeClaim("dummy claim"))
	require.Error(err, "removing a non-existing claim should return an error")
	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), []ThresholdKind{KindEntity, KindValidator})
	require.Error(err, "adding a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)
	require.EqualValues(EscrowAccount{}, acct, "account should be unchanged after failure")

	// Add some stake into the account.
	acct.Active.Balance = qtyFromInt(3_000)
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account with no claims should check out")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), []ThresholdKind{KindEntity, KindCompute})
	require.Error(err, "adding a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), []ThresholdKind{KindEntity})
	require.NoError(err, "adding a stake claim with sufficient stake should work")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	// Update an existing claim.
	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), []ThresholdKind{KindEntity, KindCompute})
	require.Error(err, "updating a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), []ThresholdKind{KindEntity, KindStorage})
	require.NoError(err, "updating a stake claim with sufficient stake should work")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), []ThresholdKind{KindEntity, KindStorage})
	require.NoError(err, "updating a stake claim with sufficient stake should work")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	// Add another claim.
	err = acct.AddStakeClaim(thresholds, StakeClaim("claim2"), []ThresholdKind{KindStorage})
	require.Error(err, "updating a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	acct.Active.Balance = qtyFromInt(13_000)

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim2"), []ThresholdKind{KindStorage})
	require.NoError(err, "adding a stake claim with sufficient stake should work")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	require.Len(acct.StakeAccumulator.Claims, 2, "stake accumulator should contain two claims")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim3"), []ThresholdKind{KindValidator})
	require.Error(err, "adding a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	// Remove an existing claim.
	err = acct.RemoveStakeClaim(StakeClaim("claim2"))
	require.NoError(err, "removing an existing claim should work")
	require.Len(acct.StakeAccumulator.Claims, 1, "stake accumulator should contain one claim")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim3"), []ThresholdKind{KindValidator})
	require.NoError(err, "adding a stake claim sufficient stake should work")
	require.Len(acct.StakeAccumulator.Claims, 2, "stake accumulator should contain two claims")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	// Reduce stake.
	acct.Active.Balance = qtyFromInt(5_000)
	err = acct.CheckStakeClaims(thresholds)
	require.Error(err, "escrow account should no longer check out")
	require.Equal(err, ErrInsufficientStake)
}

func qtyFromInt(n int) quantity.Quantity {
	q := quantity.NewQuantity()
	if err := q.FromInt64(int64(n)); err != nil {
		panic(err)
	}
	return *q
}
