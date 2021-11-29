package api

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func TestConsensusParameters(t *testing.T) {
	require := require.New(t)

	// Default consensus parameters.
	var emptyParams ConsensusParameters
	require.Error(emptyParams.SanityCheck(), "default consensus parameters should be invalid")

	// Valid thresholds.
	validThresholds := map[ThresholdKind]quantity.Quantity{
		KindEntity:            *quantity.NewQuantity(),
		KindNodeValidator:     *quantity.NewQuantity(),
		KindNodeCompute:       *quantity.NewQuantity(),
		KindNodeKeyManager:    *quantity.NewQuantity(),
		KindRuntimeCompute:    *quantity.NewQuantity(),
		KindRuntimeKeyManager: *quantity.NewQuantity(),
	}
	validThresholdsParams := ConsensusParameters{
		Thresholds:         validThresholds,
		FeeSplitWeightVote: mustInitQuantity(t, 1),
	}
	require.NoError(validThresholdsParams.SanityCheck(), "consensus parameters with valid thresholds should be valid")

	// NOTE: There is currently no way to construct invalid thresholds.

	// Degenerate fee split.
	degenerateFeeSplit := ConsensusParameters{
		Thresholds:                validThresholds,
		FeeSplitWeightPropose:     mustInitQuantity(t, 0),
		FeeSplitWeightVote:        mustInitQuantity(t, 0),
		FeeSplitWeightNextPropose: mustInitQuantity(t, 0),
	}
	require.Error(degenerateFeeSplit.SanityCheck(), "consensus parameters with degenerate fee split should be invalid")
}

func TestThresholdKind(t *testing.T) {
	require := require.New(t)

	for _, k := range ThresholdKinds {
		enc, err := k.MarshalText()
		require.NoError(err, "MarshalText")

		var d ThresholdKind
		err = d.UnmarshalText(enc)
		require.NoError(err, "UnmarshalText")
		require.Equal(k, d, "threshold kind should round-trip")
	}
}

func TestStakeThreshold(t *testing.T) {
	require := require.New(t)

	// Empty stake threshold is invalid.
	st := StakeThreshold{}
	_, err := st.Value(nil)
	require.Error(err, "empty stake threshold is invalid")

	// Global threshold reference is resolved correctly.
	tm := map[ThresholdKind]quantity.Quantity{
		KindEntity: *quantity.NewFromUint64(1_000),
	}
	kind := KindEntity
	st = StakeThreshold{Global: &kind}
	v, err := st.Value(tm)
	require.NoError(err, "global threshold reference should be resolved correctly")
	q := tm[kind]
	require.True(q.Cmp(v) == 0, "global threshold reference should be resolved correctly")

	// Constant threshold is resolved correctly.
	c := *quantity.NewFromUint64(5_000)
	st = StakeThreshold{Constant: &c}
	v, err = st.Value(tm)
	require.NoError(err, "constant threshold should be resolved correctly")
	require.True(c.Cmp(v) == 0, "constant threshold should be resolved correctly")

	// Equality checks.
	kind2 := KindEntity
	kind3 := KindNodeCompute
	c2 := *quantity.NewFromUint64(1_000)

	for _, t := range []struct {
		a     StakeThreshold
		b     StakeThreshold
		equal bool
	}{
		{StakeThreshold{Global: &kind}, StakeThreshold{Global: &kind}, true},
		{StakeThreshold{Global: &kind}, StakeThreshold{Global: &kind2}, true},
		{StakeThreshold{Global: &kind}, StakeThreshold{Global: &kind3}, false},
		{StakeThreshold{Global: &kind}, StakeThreshold{Constant: &c2}, false},
		{StakeThreshold{Constant: &c2}, StakeThreshold{Constant: &c2}, true},
		{StakeThreshold{Constant: &c}, StakeThreshold{Constant: &c2}, false},
		{StakeThreshold{}, StakeThreshold{Constant: &c2}, false},
		{StakeThreshold{}, StakeThreshold{}, false},
	} {
		require.True(t.a.Equal(&t.b) == t.equal, "stake threshold equality should work (a == b)")
		require.True(t.b.Equal(&t.a) == t.equal, "stake threshold equality should work (b == a)")
	}
}

func TestStakeAccumulator(t *testing.T) {
	require := require.New(t)

	thresholds := map[ThresholdKind]quantity.Quantity{
		KindEntity:            *quantity.NewFromUint64(1_000),
		KindNodeValidator:     *quantity.NewFromUint64(10_000),
		KindNodeCompute:       *quantity.NewFromUint64(5_000),
		KindNodeKeyManager:    *quantity.NewFromUint64(50_000),
		KindRuntimeCompute:    *quantity.NewFromUint64(2_000),
		KindRuntimeKeyManager: *quantity.NewFromUint64(1_000_000),
	}

	// Empty escrow account tests.
	var acct EscrowAccount
	err := acct.CheckStakeClaims(thresholds)
	require.NoError(err, "empty escrow account should check out")
	err = acct.RemoveStakeClaim(StakeClaim("dummy claim"))
	require.Error(err, "removing a non-existing claim should return an error")
	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), GlobalStakeThresholds(KindEntity, KindNodeValidator))
	require.Error(err, "adding a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)
	require.EqualValues(EscrowAccount{}, acct, "account should be unchanged after failure")

	// Add some stake into the account.
	acct.Active.Balance = *quantity.NewFromUint64(3_000)
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account with no claims should check out")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), GlobalStakeThresholds(KindEntity, KindNodeCompute))
	require.Error(err, "adding a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), GlobalStakeThresholds(KindEntity))
	require.NoError(err, "adding a stake claim with sufficient stake should work")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	// Update an existing claim.
	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), GlobalStakeThresholds(KindEntity, KindNodeCompute))
	require.Error(err, "updating a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), GlobalStakeThresholds(KindEntity, KindRuntimeCompute))
	require.NoError(err, "updating a stake claim with sufficient stake should work")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim1"), GlobalStakeThresholds(KindEntity, KindRuntimeCompute))
	require.NoError(err, "updating a stake claim with sufficient stake should work")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	// Add another claim.
	err = acct.AddStakeClaim(thresholds, StakeClaim("claim2"), GlobalStakeThresholds(KindRuntimeCompute))
	require.Error(err, "updating a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	acct.Active.Balance = *quantity.NewFromUint64(13_000)

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim2"), GlobalStakeThresholds(KindRuntimeCompute))
	require.NoError(err, "adding a stake claim with sufficient stake should work")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	require.Len(acct.StakeAccumulator.Claims, 2, "stake accumulator should contain two claims")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim3"), GlobalStakeThresholds(KindNodeValidator))
	require.Error(err, "adding a stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	// Add constant claim.
	q1 := *quantity.NewFromUint64(10)
	err = acct.AddStakeClaim(thresholds, StakeClaim("claimC1"), []StakeThreshold{{Constant: &q1}})
	require.NoError(err, "adding a constant stake claim with sufficient stake should work")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	q2 := *quantity.NewFromUint64(10_000)
	err = acct.AddStakeClaim(thresholds, StakeClaim("claimC2"), []StakeThreshold{{Constant: &q2}})
	require.Error(err, "adding a constant stake claim with insufficient stake should fail")
	require.Equal(err, ErrInsufficientStake)

	// Remove an existing claim.
	err = acct.RemoveStakeClaim(StakeClaim("claim2"))
	require.NoError(err, "removing an existing claim should work")
	require.Len(acct.StakeAccumulator.Claims, 2, "stake accumulator should contain two claims")

	err = acct.RemoveStakeClaim(StakeClaim("claimC1"))
	require.NoError(err, "removing an existing claim should work")
	require.Len(acct.StakeAccumulator.Claims, 1, "stake accumulator should contain one claim")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claim3"), GlobalStakeThresholds(KindNodeValidator))
	require.NoError(err, "adding a stake claim with sufficient stake should work")
	require.Len(acct.StakeAccumulator.Claims, 2, "stake accumulator should contain two claims")
	err = acct.CheckStakeClaims(thresholds)
	require.NoError(err, "escrow account should check out")

	// Add claim with empty threshold list.
	err = acct.AddStakeClaim(thresholds, StakeClaim("claimEmptyList"), []StakeThreshold{})
	require.NoError(err, "adding an empty list stake claim should work")
	err = acct.RemoveStakeClaim(StakeClaim("claimEmptyList"))
	require.NoError(err, "removing an empty claim should work")

	err = acct.AddStakeClaim(thresholds, StakeClaim("claimNilList"), nil)
	require.NoError(err, "adding an nil list stake claim should work")
	err = acct.RemoveStakeClaim(StakeClaim("claimNilList"))
	require.NoError(err, "removing an nil claim should work")

	// Reduce stake.
	acct.Active.Balance = *quantity.NewFromUint64(5_000)
	err = acct.CheckStakeClaims(thresholds)
	require.Error(err, "escrow account should no longer check out")
	require.Equal(err, ErrInsufficientStake)
}

func TestDebondingDelegationMerge(t *testing.T) {
	require := require.New(t)

	one := mustInitQuantity(t, 1)
	toAdd := DebondingDelegation{
		Shares:        mustInitQuantity(t, 10),
		DebondEndTime: api.EpochTime(100),
	}
	for _, t := range []struct {
		base      *DebondingDelegation
		msg       string
		shouldErr bool
		result    *DebondingDelegation
	}{
		{
			&DebondingDelegation{Shares: one, DebondEndTime: 1},
			"end time doesn't match",
			true,
			nil,
		},
		{
			&DebondingDelegation{Shares: one, DebondEndTime: 100},
			"merge should correctly merge debonding delegations",
			false,
			&DebondingDelegation{Shares: mustInitQuantity(t, 11), DebondEndTime: 100},
		},
	} {
		err := t.base.Merge(toAdd)
		if t.shouldErr {
			require.Error(err, t.msg)
			continue
		}
		require.NoError(err)
		require.EqualValues(t.result, t.base, t.msg)
	}
}

func TestAccountsSerialization(t *testing.T) {
	require := require.New(t)

	kind := KindNodeCompute
	// NOTE: These cases should be synced with tests in runtime/src/consensus/staking.rs.
	for _, tc := range []struct {
		rr             Account
		expectedBase64 string
	}{
		{Account{}, "oA=="},
		{Account{General: GeneralAccount{
			Balance: mustInitQuantity(t, 10),
			Nonce:   33,
		}}, "oWdnZW5lcmFsomVub25jZRghZ2JhbGFuY2VBCg=="},
		{Account{
			General: GeneralAccount{
				Allowances: map[Address]quantity.Quantity{
					CommonPoolAddress:         mustInitQuantity(t, 100),
					GovernanceDepositsAddress: mustInitQuantity(t, 33),
				},
			},
		}, "oWdnZW5lcmFsoWphbGxvd2FuY2VzolUAdU/0RxQ6XsX0cbMPhna5TVaxV1BBIVUA98Te1iET4sKC6oZyI6VE7VXWum5BZA=="},
		{Account{
			Escrow: EscrowAccount{
				Active: SharePool{
					Balance:     mustInitQuantity(t, 1100),
					TotalShares: mustInitQuantity(t, 11),
				},
				Debonding: SharePool{},
				CommissionSchedule: CommissionSchedule{
					Bounds: []CommissionRateBoundStep{
						{
							Start:   33,
							RateMin: mustInitQuantity(t, 10),
							RateMax: mustInitQuantity(t, 1000),
						},
					},
				},
				StakeAccumulator: StakeAccumulator{map[StakeClaim][]StakeThreshold{
					KindEntityName: {
						{Constant: mustInitQuantityP(t, 77)},
						{
							Global: &kind,
						},
					},
				}},
			},
		}, "oWZlc2Nyb3ejZmFjdGl2ZaJnYmFsYW5jZUIETGx0b3RhbF9zaGFyZXNBC3FzdGFrZV9hY2N1bXVsYXRvcqFmY2xhaW1zoWZlbnRpdHmCoWVjb25zdEFNoWZnbG9iYWwCc2NvbW1pc3Npb25fc2NoZWR1bGWhZmJvdW5kc4GjZXN0YXJ0GCFocmF0ZV9tYXhCA+hocmF0ZV9taW5BCg=="},
	} {
		enc := cbor.Marshal(tc.rr)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec Account
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.rr, dec, "Account serialization should round-trip")
	}
}

func TestDelegationSerialization(t *testing.T) {
	require := require.New(t)

	// NOTE: These cases should be synced with tests in runtime/src/consensus/staking.rs.
	for _, tc := range []struct {
		rr             Delegation
		expectedBase64 string
	}{
		{Delegation{}, "oWZzaGFyZXNA"},
		{
			Delegation{Shares: mustInitQuantity(t, 100)},
			"oWZzaGFyZXNBZA==",
		},
	} {
		enc := cbor.Marshal(tc.rr)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec Delegation
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.rr, dec, "Delegation serialization should round-trip")
	}
}

func TestDebondingDelegationSerialization(t *testing.T) {
	require := require.New(t)

	// NOTE: These cases should be synced with tests in runtime/src/consensus/staking.rs.
	for _, tc := range []struct {
		rr             DebondingDelegation
		expectedBase64 string
	}{
		{DebondingDelegation{}, "omZzaGFyZXNAamRlYm9uZF9lbmQA"},
		{
			DebondingDelegation{
				Shares:        mustInitQuantity(t, 100),
				DebondEndTime: 23,
			},
			"omZzaGFyZXNBZGpkZWJvbmRfZW5kFw==",
		},
	} {
		enc := cbor.Marshal(tc.rr)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec DebondingDelegation
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.rr, dec, "DebondingDelegation serialization should round-trip")
	}
}
