package state

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
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

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	fac := memorySigner.NewFactory()

	// Generate escrow account.
	escrowSigner, err := fac.Generate(signature.SignerEntity, rand.Reader)
	require.NoError(err, "generating escrow signer")
	escrowAddr := staking.NewAddress(escrowSigner.Public())

	var escrowAccount staking.Account
	err = s.SetAccount(ctx, escrowAddr, &escrowAccount)
	require.NoError(err, "SetAccount")

	// Generate delegator accounts.
	var delegatorAddrs []staking.Address
	// Store expected delegations.
	expectedDelegations := make(map[staking.Address]map[staking.Address]*staking.Delegation)
	expectedDelegations[escrowAddr] = map[staking.Address]*staking.Delegation{}
	expectedDebDelegations := make(map[staking.Address]map[staking.Address][]*staking.DebondingDelegation)
	expectedDebDelegations[escrowAddr] = map[staking.Address][]*staking.DebondingDelegation{}

	for i := int64(1); i <= int64(numDelegatorAccounts); i++ {
		signer, serr := fac.Generate(signature.SignerEntity, rand.Reader)
		require.NoError(serr, "memory signer factory Generate account")
		addr := staking.NewAddress(signer.Public())

		delegatorAddrs = append(delegatorAddrs, addr)

		// Init account.
		var account staking.Account
		account.General.Nonce = uint64(i)
		err = account.General.Balance.FromBigInt(big.NewInt(2 * i * 100))
		require.NoError(err, "initialize delegator account general balance")

		// Init delegation.
		var del staking.Delegation
		err = escrowAccount.Escrow.Active.Deposit(&del.Shares, &account.General.Balance, mustInitQuantityP(t, i*100))
		require.NoError(err, "active escrow deposit")
		expectedDelegations[escrowAddr][addr] = &del

		// Init debonding delegation.
		var deb staking.DebondingDelegation
		deb.DebondEndTime = epochtime.EpochTime(i)
		err = escrowAccount.Escrow.Debonding.Deposit(&deb.Shares, &account.General.Balance, mustInitQuantityP(t, i*100))
		require.NoError(err, "debonding escrow deposit")
		expectedDebDelegations[escrowAddr][addr] = []*staking.DebondingDelegation{&deb}

		// Update state.
		err = s.SetAccount(ctx, addr, &account)
		require.NoError(err, "SetAccount")
		err = s.SetDelegation(ctx, addr, escrowAddr, &del)
		require.NoError(err, "SetDelegation")
		err = s.SetDebondingDelegation(ctx, addr, escrowAddr, uint64(i), &deb)
		require.NoError(err, "SetDebondingDelegation")
	}

	// Test delegation queries.
	for _, addr := range delegatorAddrs {
		accDelegations, derr := s.DelegationsFor(ctx, addr)
		require.NoError(derr, "DelegationsFor")
		expectedDelegation := map[staking.Address]*staking.Delegation{
			escrowAddr: expectedDelegations[escrowAddr][addr],
		}
		require.EqualValues(expectedDelegation, accDelegations, "DelegationsFor account should match expected delegations")
	}
	delegations, err := s.Delegations(ctx)
	require.NoError(err, "state.Delegations")
	require.EqualValues(expectedDelegations, delegations, "Delegations should match expected delegations")

	// Test debonding delegation queries.
	for _, addr := range delegatorAddrs {
		accDebDelegations, derr := s.DebondingDelegationsFor(ctx, addr)
		require.NoError(derr, "DebondingDelegationsFor")
		expectedDebDelegation := map[staking.Address][]*staking.DebondingDelegation{
			escrowAddr: expectedDebDelegations[escrowAddr][addr],
		}
		require.EqualValues(expectedDebDelegation, accDebDelegations, "DebondingDelegationsFor account should match expected")
	}
	debDelegations, err := s.DebondingDelegations(ctx)
	require.NoError(err, "state.DebondingDelegations")
	require.EqualValues(expectedDebDelegations, debDelegations, "DebondingDelegations should match expected")
}

func TestRewardAndSlash(t *testing.T) {
	require := require.New(t)

	delegatorSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "generating delegator signer")
	delegatorAddr := staking.NewAddress(delegatorSigner.Public())
	delegatorAccount := &staking.Account{}
	delegatorAccount.General.Nonce = 10
	err = delegatorAccount.General.Balance.FromBigInt(big.NewInt(300))
	require.NoError(err, "initialize delegator account general balance")

	escrowSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "generating escrow signer")
	escrowAddr := staking.NewAddress(escrowSigner.Public())
	escrowAddrAsList := []staking.Address{escrowAddr}
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

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	err = s.SetConsensusParameters(ctx, &staking.ConsensusParameters{
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
	require.NoError(err, "SetConsensusParameters")
	err = s.SetCommonPool(ctx, mustInitQuantityP(t, 10000))
	require.NoError(err, "SetCommonPool")

	err = s.SetAccount(ctx, delegatorAddr, delegatorAccount)
	require.NoError(err, "SetAccount")
	err = s.SetAccount(ctx, escrowAddr, escrowAccount)
	require.NoError(err, "SetAccount")
	err = s.SetDelegation(ctx, delegatorAddr, escrowAddr, del)
	require.NoError(err, "SetDelegation")
	err = s.SetDebondingDelegation(ctx, delegatorAddr, escrowAddr, 1, &deb)
	require.NoError(err, "SetDebondingDelegation")

	// Epoch 10 is during the first step.
	require.NoError(s.AddRewards(ctx, 10, mustInitQuantityP(t, 100), escrowAddrAsList), "add rewards epoch 10")

	// 100% gain.
	delegatorAccount, err = s.Account(ctx, delegatorAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 100), delegatorAccount.General.Balance, "reward first step - delegator general")
	escrowAccount, err = s.Account(ctx, escrowAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 200), escrowAccount.Escrow.Active.Balance, "reward first step - escrow active escrow")
	require.Equal(mustInitQuantity(t, 100), escrowAccount.Escrow.Debonding.Balance, "reward first step - escrow debonding escrow")
	// Reward is 100 tokens, with 80 added to the pool and 20 deposited as commission.
	// We add to the pool first, so the delegation becomes 100 shares : 180 tokens.
	// Then we deposit the 20 for commission, which comes out to 11 shares.
	del, err = s.Delegation(ctx, delegatorAddr, escrowAddr)
	require.NoError(err, "Delegation")
	require.Equal(mustInitQuantity(t, 100), del.Shares, "reward first step - delegation shares")
	escrowSelfDel, err := s.Delegation(ctx, escrowAddr, escrowAddr)
	require.NoError(err, "Delegation")
	require.Equal(mustInitQuantity(t, 11), escrowSelfDel.Shares, "reward first step - escrow self delegation shares")
	commonPool, err := s.CommonPool(ctx)
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9900), commonPool, "reward first step - common pool")

	// Epoch 30 is in the second step.
	require.NoError(s.AddRewards(ctx, 30, mustInitQuantityP(t, 100), escrowAddrAsList), "add rewards epoch 30")

	// 50% gain.
	escrowAccount, err = s.Account(ctx, escrowAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward boundary epoch - escrow active escrow")
	commonPool, err = s.CommonPool(ctx)
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9800), commonPool, "reward first step - common pool")

	// Epoch 99 is after the end of the schedule
	require.NoError(s.AddRewards(ctx, 99, mustInitQuantityP(t, 100), escrowAddrAsList), "add rewards epoch 99")

	// No change.
	escrowAccount, err = s.Account(ctx, escrowAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward late epoch - escrow active escrow")

	slashedNonzero, err := s.SlashEscrow(ctx, escrowAddr, mustInitQuantityP(t, 40))
	require.NoError(err, "slash escrow")
	require.True(slashedNonzero, "slashed nonzero")

	// 40 token loss.
	delegatorAccount, err = s.Account(ctx, delegatorAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 100), delegatorAccount.General.Balance, "slash - delegator general")
	escrowAccount, err = s.Account(ctx, escrowAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 270), escrowAccount.Escrow.Active.Balance, "slash - escrow active escrow")
	require.Equal(mustInitQuantity(t, 90), escrowAccount.Escrow.Debonding.Balance, "slash - escrow debonding escrow")
	commonPool, err = s.CommonPool(ctx)
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9840), commonPool, "slash - common pool")

	// Epoch 10 is during the first step.
	require.NoError(s.AddRewardSingleAttenuated(ctx, 10, mustInitQuantityP(t, 10), 5, 10, escrowAddr), "add attenuated rewards epoch 30")

	// 5% gain.
	escrowAccount, err = s.Account(ctx, escrowAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 283), escrowAccount.Escrow.Active.Balance, "attenuated reward - escrow active escrow")
	commonPool, err = s.CommonPool(ctx)
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9827), commonPool, "reward attenuated - common pool")
}

func TestEpochSigning(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	es, err := s.EpochSigning(ctx)
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

	err = s.SetEpochSigning(ctx, es)
	require.NoError(err, "SetEpochSigning")
	esRoundTrip, err := s.EpochSigning(ctx)
	require.NoError(err, "load epoch signing info 2")
	require.Equal(es, esRoundTrip, "epoch signing info round trip")

	eligibleEntities, err := es.EligibleEntities(3, 4)
	require.NoError(err, "determining eligible entities")
	require.Len(eligibleEntities, 2, "eligible entities")
	require.NotContains(eligibleEntities, truant, "'truant' not eligible")
	require.Contains(eligibleEntities, exact, "'exact' eligible")
	require.Contains(eligibleEntities, perfect, "'perfect' eligible")

	err = s.ClearEpochSigning(ctx)
	require.NoError(err, "ClearEpochSigning")
	esClear, err := s.EpochSigning(ctx)
	require.NoError(err, "load cleared epoch signing info")
	require.Zero(esClear.Total, "cleared epoch signing info total")
	require.Empty(esClear.ByEntity, "cleared epoch signing info by entity")
}
