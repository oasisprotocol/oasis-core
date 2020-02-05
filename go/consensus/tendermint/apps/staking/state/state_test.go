package state

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/iavl"
	dbm "github.com/tendermint/tm-db"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func mustInitQuantity(t *testing.T, i int64) (q quantity.Quantity) {
	require.NoError(t, q.FromBigInt(big.NewInt(i)), "FromBigInt")
	return
}

func mustInitQuantityP(t *testing.T, i int64) *quantity.Quantity {
	q := mustInitQuantity(t, i)
	return &q
}

func TestRewardAndSlash(t *testing.T) {
	delegatorSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "generating delegator signer")
	delegatorID := delegatorSigner.Public()
	delegatorAccount := &staking.Account{}
	delegatorAccount.General.Nonce = 10
	require.NoError(t, delegatorAccount.General.Balance.FromBigInt(big.NewInt(300)), "initialize delegator account general balance")

	escrowSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "generating escrow signer")
	escrowID := escrowSigner.Public()
	escrowAccountOnly := []signature.PublicKey{escrowID}
	escrowAccount := &staking.Account{}
	escrowAccount.Escrow.CommissionSchedule = staking.CommissionSchedule{
		Rates: []staking.CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 20_000), // 20%
			},
		},
		Bounds: []staking.CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	require.NoError(t, escrowAccount.Escrow.CommissionSchedule.PruneAndValidateForGenesis(&staking.CommissionScheduleRules{
		RateChangeInterval: 10,
		RateBoundLead:      30,
		MaxRateSteps:       4,
		MaxBoundSteps:      12,
	}, 0), "commission schedule")

	del := &staking.Delegation{}
	require.NoError(t, escrowAccount.Escrow.Active.Deposit(&del.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100)), "active escrow deposit")

	deb := &staking.DebondingDelegation{}
	deb.DebondEndTime = 21
	require.NoError(t, escrowAccount.Escrow.Debonding.Deposit(&deb.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100)), "debonding escrow deposit")

	db := dbm.NewMemDB()
	tree := iavl.NewMutableTree(db, 128)
	s := NewMutableState(tree)

	s.SetConsensusParameters(&staking.ConsensusParameters{
		DebondingInterval: 21,
		RewardSchedule: []staking.RewardStep{
			{
				Until: 30,
				Scale: mustInitQuantity(t, 1000),
			},
			{
				Until: 40,
				Scale: mustInitQuantity(t, 500),
			},
		},
		CommissionScheduleRules: staking.CommissionScheduleRules{
			RateChangeInterval: 10,
			RateBoundLead:      30,
			MaxRateSteps:       4,
			MaxBoundSteps:      12,
		},
	})
	s.SetCommonPool(mustInitQuantityP(t, 10000))

	s.SetAccount(delegatorID, delegatorAccount)
	s.SetAccount(escrowID, escrowAccount)
	s.SetDelegation(delegatorID, escrowID, del)
	s.SetDebondingDelegation(delegatorID, escrowID, 1, deb)

	// Epoch 10 is during the first step.
	require.NoError(t, s.AddRewards(10, mustInitQuantityP(t, 100), escrowAccountOnly), "add rewards epoch 10")

	// 100% gain.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(t, mustInitQuantity(t, 100), delegatorAccount.General.Balance, "reward first step - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 200), escrowAccount.Escrow.Active.Balance, "reward first step - escrow active escrow")
	require.Equal(t, mustInitQuantity(t, 100), escrowAccount.Escrow.Debonding.Balance, "reward first step - escrow debonding escrow")
	// Reward is 100 tokens, with 80 added to the pool and 20 deposited as commission.
	// We add to the pool first, so the delegation becomes 100 shares : 180 tokens.
	// Then we deposit the 20 for commission, which comes out to 11 shares.
	del = s.Delegation(delegatorID, escrowID)
	require.Equal(t, mustInitQuantity(t, 100), del.Shares, "reward first step - delegation shares")
	escrowSelfDel := s.Delegation(escrowID, escrowID)
	require.Equal(t, mustInitQuantity(t, 11), escrowSelfDel.Shares, "reward first step - escrow self delegation shares")
	commonPool, err := s.CommonPool()
	require.NoError(t, err, "load common pool")
	require.Equal(t, mustInitQuantityP(t, 9900), commonPool, "reward first step - common pool")

	// Epoch 30 is in the second step.
	require.NoError(t, s.AddRewards(30, mustInitQuantityP(t, 100), escrowAccountOnly), "add rewards epoch 30")

	// 50% gain.
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward boundary epoch - escrow active escrow")
	commonPool, err = s.CommonPool()
	require.NoError(t, err, "load common pool")
	require.Equal(t, mustInitQuantityP(t, 9800), commonPool, "reward first step - common pool")

	// Epoch 99 is after the end of the schedule
	require.NoError(t, s.AddRewards(99, mustInitQuantityP(t, 100), escrowAccountOnly), "add rewards epoch 99")

	// No change.
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward late epoch - escrow active escrow")

	slashedNonzero, err := s.SlashEscrow(abci.NewMockContext(abci.ContextDeliverTx, time.Now()), escrowID, mustInitQuantityP(t, 40))
	require.NoError(t, err, "slash escrow")
	require.True(t, slashedNonzero, "slashed nonzero")

	// 40 token loss.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(t, mustInitQuantity(t, 100), delegatorAccount.General.Balance, "slash - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 270), escrowAccount.Escrow.Active.Balance, "slash - escrow active escrow")
	require.Equal(t, mustInitQuantity(t, 90), escrowAccount.Escrow.Debonding.Balance, "slash - escrow debonding escrow")
	commonPool, err = s.CommonPool()
	require.NoError(t, err, "load common pool")
	require.Equal(t, mustInitQuantityP(t, 9840), commonPool, "slash - common pool")

	// Epoch 10 is during the first step.
	require.NoError(t, s.AddRewardSingleAttenuated(10, mustInitQuantityP(t, 10), 5, 10, escrowID), "add attenuated rewards epoch 30")

	// 5% gain.
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 283), escrowAccount.Escrow.Active.Balance, "attenuated reward - escrow active escrow")
	commonPool, err = s.CommonPool()
	require.NoError(t, err, "load common pool")
	require.Equal(t, mustInitQuantityP(t, 9827), commonPool, "reward attenuated - common pool")
}

func TestEpochSigning(t *testing.T) {
	db := dbm.NewMemDB()
	tree := iavl.NewMutableTree(db, 128)
	s := NewMutableState(tree)

	es, err := s.EpochSigning()
	require.NoError(t, err, "load epoch signing info")
	require.Zero(t, es.Total, "empty epoch signing info total")
	require.Empty(t, es.ByEntity, "empty epoch signing info by entity")

	var truant, exact, perfect signature.PublicKey
	require.NoError(t, truant.UnmarshalHex("1111111111111111111111111111111111111111111111111111111111111111"), "initializing 'truant' ID")
	require.NoError(t, exact.UnmarshalHex("3333333333333333333333333333333333333333333333333333333333333333"), "initializing 'exact' ID")
	require.NoError(t, perfect.UnmarshalHex("4444444444444444444444444444444444444444444444444444444444444444"), "initializing 'perfect' ID")

	require.NoError(t, es.Update([]signature.PublicKey{truant, exact, perfect}), "updating epoch signing info")
	require.NoError(t, es.Update([]signature.PublicKey{exact, perfect}), "updating epoch signing info")
	require.NoError(t, es.Update([]signature.PublicKey{exact, perfect}), "updating epoch signing info")
	require.NoError(t, es.Update([]signature.PublicKey{perfect}), "updating epoch signing info")
	require.EqualValues(t, 4, es.Total, "populated epoch signing info total")
	require.Len(t, es.ByEntity, 3, "populated epoch signing info by entity")

	s.SetEpochSigning(es)
	esRoundTrip, err := s.EpochSigning()
	require.NoError(t, err, "load epoch signing info 2")
	require.Equal(t, es, esRoundTrip, "epoch signing info round trip")

	eligibleEntities, err := es.EligibleEntities(3, 4)
	require.NoError(t, err, "determining eligible entities")
	require.Len(t, eligibleEntities, 2, "eligible entities")
	require.NotContains(t, eligibleEntities, truant, "'truant' not eligible")
	require.Contains(t, eligibleEntities, exact, "'exact' eligible")
	require.Contains(t, eligibleEntities, perfect, "'perfect' eligible")

	s.ClearEpochSigning()
	esClear, err := s.EpochSigning()
	require.NoError(t, err, "load cleared epoch signing info")
	require.Zero(t, esClear.Total, "cleared epoch signing info total")
	require.Empty(t, esClear.ByEntity, "cleared epoch signing info by entity")
}
