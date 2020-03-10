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
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func mustInitQuantity(t *testing.T, i int64) (q quantity.Quantity) {
	err := q.FromBigInt(big.NewInt(i))
	require.NoError(t, err, "FromBigInt")
	return
}

func mustInitQuantityP(t *testing.T, i int64) *quantity.Quantity {
	q := mustInitQuantity(t, i)
	return &q
}

func TestDelegationQueries(t *testing.T) {
	numDelegatorAccounts := 5

	require := require.New(t)

	db := dbm.NewMemDB()
	tree := iavl.NewMutableTree(db, 128)
	s := NewMutableState(tree)

	fac := memorySigner.NewFactory()

	// Generate escrow account.
	escrowSigner, err := fac.Generate(signature.SignerEntity, rand.Reader)
	require.NoError(err, "generating escrow signer")
	escrowID := escrowSigner.Public()

	var escrowAccount staking.Account
	s.SetAccount(escrowID, &escrowAccount)

	// Generate delegator accounts.
	var delegatorIDs []signature.PublicKey
	// Store expected delegations.
	expectedDelegations := make(map[signature.PublicKey]map[signature.PublicKey]*staking.Delegation)
	expectedDelegations[escrowID] = map[signature.PublicKey]*staking.Delegation{}
	expectedDebDelegations := make(map[signature.PublicKey]map[signature.PublicKey][]*staking.DebondingDelegation)
	expectedDebDelegations[escrowID] = map[signature.PublicKey][]*staking.DebondingDelegation{}

	for i := int64(1); i <= int64(numDelegatorAccounts); i++ {
		signer, serr := fac.Generate(signature.SignerEntity, rand.Reader)
		require.NoError(serr, "memory signer factory Generate account")
		id := signer.Public()

		delegatorIDs = append(delegatorIDs, id)

		// Init account.
		var account staking.Account
		account.General.Nonce = uint64(i)
		err = account.General.Balance.FromBigInt(big.NewInt(2 * i * 100))
		require.NoError(err, "initialize delegator account general balance")

		// Init delegation.
		var del staking.Delegation
		err = escrowAccount.Escrow.Active.Deposit(&del.Shares, &account.General.Balance, mustInitQuantityP(t, i*100))
		require.NoError(err, "active escrow deposit")
		expectedDelegations[escrowID][id] = &del

		// Init debonding delegation.
		var deb staking.DebondingDelegation
		deb.DebondEndTime = epochtime.EpochTime(i)
		err = escrowAccount.Escrow.Debonding.Deposit(&deb.Shares, &account.General.Balance, mustInitQuantityP(t, i*100))
		require.NoError(err, "debonding escrow deposit")
		expectedDebDelegations[escrowID][id] = []*staking.DebondingDelegation{&deb}

		// Update state.
		s.SetAccount(id, &account)
		s.SetDelegation(id, escrowID, &del)
		s.SetDebondingDelegation(id, escrowID, uint64(i), &deb)
	}

	// Test delegation queries.
	for _, id := range delegatorIDs {
		accDelegations, derr := s.DelegationsFor(id)
		require.NoError(derr, "DelegationsFor")
		expectedDelegation := map[signature.PublicKey]*staking.Delegation{
			escrowID: expectedDelegations[escrowID][id],
		}
		require.EqualValues(expectedDelegation, accDelegations, "DelegationsFor account should match expected delegations")
	}
	delegations, err := s.Delegations()
	require.NoError(err, "state.Delegations")
	require.EqualValues(expectedDelegations, delegations, "Delegations should match expected delegations")

	// Test debonding delegation queries.
	for _, id := range delegatorIDs {
		accDebDelegations, derr := s.DebondingDelegationsFor(id)
		require.NoError(derr, "DebondingDelegationsFor")
		expectedDebDelegation := map[signature.PublicKey][]*staking.DebondingDelegation{
			escrowID: expectedDebDelegations[escrowID][id],
		}
		require.EqualValues(expectedDebDelegation, accDebDelegations, "DebondingDelegationsFor account should match expected")
	}
	debDelegations, err := s.DebondingDelegations()
	require.NoError(err, "state.DebondingDelegations")
	require.EqualValues(expectedDebDelegations, debDelegations, "DebondingDelegations should match expected")
}

func TestRewardAndSlash(t *testing.T) {
	require := require.New(t)

	delegatorSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "generating delegator signer")
	delegatorID := delegatorSigner.Public()
	delegatorAccount := &staking.Account{}
	delegatorAccount.General.Nonce = 10
	err = delegatorAccount.General.Balance.FromBigInt(big.NewInt(300))
	require.NoError(err, "initialize delegator account general balance")

	escrowSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "generating escrow signer")
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
	err = escrowAccount.Escrow.CommissionSchedule.PruneAndValidateForGenesis(
		&staking.CommissionScheduleRules{
			RateChangeInterval: 10,
			RateBoundLead:      30,
			MaxRateSteps:       4,
			MaxBoundSteps:      12,
		}, 0)
	require.NoError(err, "commission schedule")

	del := &staking.Delegation{}
	err = escrowAccount.Escrow.Active.Deposit(&del.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100))
	require.NoError(err, "active escrow deposit")

	var deb staking.DebondingDelegation
	deb.DebondEndTime = 21
	err = escrowAccount.Escrow.Debonding.Deposit(&deb.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100))
	require.NoError(err, "debonding escrow deposit")

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
	s.SetDebondingDelegation(delegatorID, escrowID, 1, &deb)

	// Epoch 10 is during the first step.
	err = s.AddRewards(10, mustInitQuantityP(t, 100), escrowAccountOnly)
	require.NoError(err, "add rewards epoch 10")

	// 100% gain.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(mustInitQuantity(t, 100), delegatorAccount.General.Balance, "reward first step - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(mustInitQuantity(t, 200), escrowAccount.Escrow.Active.Balance, "reward first step - escrow active escrow")
	require.Equal(mustInitQuantity(t, 100), escrowAccount.Escrow.Debonding.Balance, "reward first step - escrow debonding escrow")
	// Reward is 100 tokens, with 80 added to the pool and 20 deposited as commission.
	// We add to the pool first, so the delegation becomes 100 shares : 180 tokens.
	// Then we deposit the 20 for commission, which comes out to 11 shares.
	del = s.Delegation(delegatorID, escrowID)
	require.Equal(mustInitQuantity(t, 100), del.Shares, "reward first step - delegation shares")
	escrowSelfDel := s.Delegation(escrowID, escrowID)
	require.Equal(mustInitQuantity(t, 11), escrowSelfDel.Shares, "reward first step - escrow self delegation shares")
	commonPool, err := s.CommonPool()
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9900), commonPool, "reward first step - common pool")

	// Epoch 30 is in the second step.
	require.NoError(s.AddRewards(30, mustInitQuantityP(t, 100), escrowAccountOnly), "add rewards epoch 30")

	// 50% gain.
	escrowAccount = s.Account(escrowID)
	require.Equal(mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward boundary epoch - escrow active escrow")
	commonPool, err = s.CommonPool()
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9800), commonPool, "reward first step - common pool")

	// Epoch 99 is after the end of the schedule
	err = s.AddRewards(99, mustInitQuantityP(t, 100), escrowAccountOnly)
	require.NoError(err, "add rewards epoch 99")

	// No change.
	escrowAccount = s.Account(escrowID)
	require.Equal(mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward late epoch - escrow active escrow")

	slashedNonzero, err := s.SlashEscrow(abci.NewMockContext(abci.ContextDeliverTx, time.Now()), escrowID, mustInitQuantityP(t, 40))
	require.NoError(err, "slash escrow")
	require.True(slashedNonzero, "slashed nonzero")

	// 40 token loss.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(mustInitQuantity(t, 100), delegatorAccount.General.Balance, "slash - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(mustInitQuantity(t, 270), escrowAccount.Escrow.Active.Balance, "slash - escrow active escrow")
	require.Equal(mustInitQuantity(t, 90), escrowAccount.Escrow.Debonding.Balance, "slash - escrow debonding escrow")
	commonPool, err = s.CommonPool()
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9840), commonPool, "slash - common pool")

	// Epoch 10 is during the first step.
	err = s.AddRewardSingleAttenuated(10, mustInitQuantityP(t, 10), 5, 10, escrowID)
	require.NoError(err, "add attenuated rewards epoch 30")

	// 5% gain.
	escrowAccount = s.Account(escrowID)
	require.Equal(mustInitQuantity(t, 283), escrowAccount.Escrow.Active.Balance, "attenuated reward - escrow active escrow")
	commonPool, err = s.CommonPool()
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9827), commonPool, "reward attenuated - common pool")
}

func TestEpochSigning(t *testing.T) {
	require := require.New(t)

	db := dbm.NewMemDB()
	tree := iavl.NewMutableTree(db, 128)
	s := NewMutableState(tree)

	es, err := s.EpochSigning()
	require.NoError(err, "load epoch signing info")
	require.Zero(es.Total, "empty epoch signing info total")
	require.Empty(es.ByEntity, "empty epoch signing info by entity")

	var truant, exact, perfect signature.PublicKey
	err = truant.UnmarshalHex("1111111111111111111111111111111111111111111111111111111111111111")
	require.NoError(err, "initializing 'truant' ID")
	err = exact.UnmarshalHex("3333333333333333333333333333333333333333333333333333333333333333")
	require.NoError(err, "initializing 'exact' ID")
	err = perfect.UnmarshalHex("4444444444444444444444444444444444444444444444444444444444444444")
	require.NoError(err, "initializing 'perfect' ID")

	err = es.Update([]signature.PublicKey{truant, exact, perfect})
	require.NoError(err, "updating epoch signing info")
	err = es.Update([]signature.PublicKey{exact, perfect})
	require.NoError(err, "updating epoch signing info")
	err = es.Update([]signature.PublicKey{exact, perfect})
	require.NoError(err, "updating epoch signing info")
	err = es.Update([]signature.PublicKey{perfect})
	require.NoError(err, "updating epoch signing info")
	require.EqualValues(4, es.Total, "populated epoch signing info total")
	require.Len(es.ByEntity, 3, "populated epoch signing info by entity")

	s.SetEpochSigning(es)
	esRoundTrip, err := s.EpochSigning()
	require.NoError(err, "load epoch signing info 2")
	require.Equal(es, esRoundTrip, "epoch signing info round trip")

	eligibleEntities, err := es.EligibleEntities(3, 4)
	require.NoError(err, "determining eligible entities")
	require.Len(eligibleEntities, 2, "eligible entities")
	require.NotContains(eligibleEntities, truant, "'truant' not eligible")
	require.Contains(eligibleEntities, exact, "'exact' eligible")
	require.Contains(eligibleEntities, perfect, "'perfect' eligible")

	s.ClearEpochSigning()
	esClear, err := s.EpochSigning()
	require.NoError(err, "load cleared epoch signing info")
	require.Zero(esClear.Total, "cleared epoch signing info total")
	require.Empty(esClear.ByEntity, "cleared epoch signing info by entity")
}
