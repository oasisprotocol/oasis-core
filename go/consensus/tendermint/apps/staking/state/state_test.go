package state

import (
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
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
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
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
		var newShares *quantity.Quantity
		newShares, err = escrowAccount.Escrow.Active.Deposit(&del.Shares, &account.General.Balance, mustInitQuantityP(t, i*100))
		require.NoError(err, "active escrow deposit")
		require.Equal(newShares, &del.Shares, "new shares should equal initial delegation")
		expectedDelegations[escrowAddr][addr] = &del

		// Init debonding delegation.
		var deb staking.DebondingDelegation
		deb.DebondEndTime = beacon.EpochTime(i)
		newShares, err = escrowAccount.Escrow.Debonding.Deposit(&deb.Shares, &account.General.Balance, mustInitQuantityP(t, i*100))
		require.NoError(err, "debonding escrow deposit")
		require.Equal(newShares, &del.Shares, "new shares should equal initial debonding delegation")
		expectedDebDelegations[escrowAddr][addr] = []*staking.DebondingDelegation{&deb}

		// Update state.
		err = s.SetAccount(ctx, addr, &account)
		require.NoError(err, "SetAccount")
		err = s.SetDelegation(ctx, addr, escrowAddr, &del)
		require.NoError(err, "SetDelegation")
		err = s.SetDebondingDelegation(ctx, addr, escrowAddr, deb.DebondEndTime, &deb)
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

func TestDebondingDelegation(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()
	s := NewMutableState(ctx.State())

	fac := memorySigner.NewFactory()
	// Generate accounts.
	acc1Signer, err := fac.Generate(signature.SignerEntity, rand.Reader)
	require.NoError(err, "generating account signer")
	acc1Addr := staking.NewAddress(acc1Signer.Public())
	acc2Signer, err := fac.Generate(signature.SignerEntity, rand.Reader)
	require.NoError(err, "generating account signer")
	acc2Addr := staking.NewAddress(acc2Signer.Public())
	acc3Signer, err := fac.Generate(signature.SignerEntity, rand.Reader)
	require.NoError(err, "generating account signer")
	acc3Addr := staking.NewAddress(acc3Signer.Public())

	// Initial debonding delegation.
	deb := staking.DebondingDelegation{
		Shares:        mustInitQuantity(t, 100),
		DebondEndTime: beacon.EpochTime(10),
	}
	deb2 := staking.DebondingDelegation{
		Shares:        mustInitQuantity(t, 100),
		DebondEndTime: beacon.EpochTime(20),
	}
	deb3 := staking.DebondingDelegation{
		Shares:        mustInitQuantity(t, 10),
		DebondEndTime: beacon.EpochTime(10),
	}
	require.NoError(s.SetDebondingDelegation(ctx, acc1Addr, acc2Addr, deb.DebondEndTime, &deb), "SetDebondingDelegation")

	// Add debonding delegation for same epoch, but different account.
	require.NoError(s.SetDebondingDelegation(ctx, acc1Addr, acc3Addr, deb.DebondEndTime, &deb), "SetDebondingDelegation")

	// Add debonding delegation for different epoch.
	require.NoError(s.SetDebondingDelegation(ctx, acc1Addr, acc2Addr, deb2.DebondEndTime, &deb2), "SetDebondingDelegation")

	// Add debonding delegation for same epoch and account.
	// Delegation should merge with the existing debonding delegation.
	require.NoError(s.SetDebondingDelegation(ctx, acc1Addr, acc2Addr, deb.DebondEndTime, &deb3), "SetDebondingDelegation")

	// Query final state.
	dds, err := s.DebondingDelegationsFor(ctx, acc1Addr)
	require.NoError(err, "DebondingDelegations")
	expectedDds := map[staking.Address][]*staking.DebondingDelegation{
		acc2Addr: {
			// Merged deb & deb3.
			{Shares: mustInitQuantity(t, 110), DebondEndTime: beacon.EpochTime(10)},
			&deb2,
		},
		acc3Addr: {
			&deb,
		},
	}
	require.EqualValues(expectedDds, dds, "expected debonding delegations should exist")
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
	_, err = escrowAccount.Escrow.Active.Deposit(&del.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100))
	require.NoError(err, "active escrow deposit")

	var deb staking.DebondingDelegation
	deb.DebondEndTime = 21
	_, err = escrowAccount.Escrow.Debonding.Deposit(&deb.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100))
	require.NoError(err, "debonding escrow deposit")

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
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
	require.NoError(s.AddRewards(ctx, 10, mustInitQuantityP(t, 100_000), escrowAddrAsList), "add rewards epoch 10")

	// Adding rewards should emit the correct events.
	evs := ctx.GetEvents()
	require.Len(evs, 3, "adding rewards should emit 3 events")
	for _, ev := range evs {
		require.Equal(abciAPI.EventTypeForApp(AppName), ev.Type, "all emitted events should be staking events")
		require.Len(ev.Attributes, 1, "each event should have a single attribute")

		switch string(ev.Attributes[0].Key) {
		case "add_escrow":
			var v staking.AddEscrowEvent
			err = cbor.Unmarshal(ev.Attributes[0].Value, &v)
			require.NoError(err, "malformed add escrow event")
		case "transfer":
			var v staking.TransferEvent
			err = cbor.Unmarshal(ev.Attributes[0].Value, &v)
			require.NoError(err, "malformed add escrow event")
		default:
			t.Fatalf("unexpected event key: %+v", ev.Attributes[0].Key)
		}
	}
	require.Equal("add_escrow", string(evs[0].Attributes[0].Key), "first event should be an add escrow event")
	require.Equal("transfer", string(evs[1].Attributes[0].Key), "second event should be a transfer event")
	require.Equal("add_escrow", string(evs[2].Attributes[0].Key), "second event should be an add escrow event")

	// 100% gain.
	delegatorAccount, err = s.Account(ctx, delegatorAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 100), delegatorAccount.General.Balance, "reward first step - delegator general")
	escrowAccount, err = s.Account(ctx, escrowAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 200), escrowAccount.Escrow.Active.Balance, "reward first step - escrow active escrow")
	require.Equal(mustInitQuantity(t, 100), escrowAccount.Escrow.Debonding.Balance, "reward first step - escrow debonding escrow")
	// Reward is 100 base units, with 80 added to the pool and 20 deposited as commission.
	// We add to the pool first, so the delegation becomes 100 shares : 180 base units.
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
	require.NoError(s.AddRewards(ctx, 30, mustInitQuantityP(t, 100_000), escrowAddrAsList), "add rewards epoch 30")

	// 50% gain.
	escrowAccount, err = s.Account(ctx, escrowAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward boundary epoch - escrow active escrow")
	commonPool, err = s.CommonPool(ctx)
	require.NoError(err, "load common pool")
	require.Equal(mustInitQuantityP(t, 9800), commonPool, "reward first step - common pool")

	// Epoch 99 is after the end of the schedule
	require.NoError(s.AddRewards(ctx, 99, mustInitQuantityP(t, 100_000), escrowAddrAsList), "add rewards epoch 99")

	// No change.
	escrowAccount, err = s.Account(ctx, escrowAddr)
	require.NoError(err, "Account")
	require.Equal(mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward late epoch - escrow active escrow")

	slashed, err := s.SlashEscrow(ctx, escrowAddr, mustInitQuantityP(t, 40))
	require.NoError(err, "slash escrow")
	require.False(slashed.IsZero(), "slashed nonzero")

	// Loss of 40 base units.
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

	ctx = appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Epoch 10 is during the first step.
	require.NoError(s.AddRewardSingleAttenuated(ctx, 10, mustInitQuantityP(t, 10_000), 5, 10, escrowAddr), "add attenuated rewards epoch 30")

	// Adding rewards should emit the correct events.
	evs = ctx.GetEvents()
	require.Len(evs, 3, "adding rewards should emit 3 events")
	for _, ev := range evs {
		require.Equal(abciAPI.EventTypeForApp(AppName), ev.Type, "all emitted events should be staking events")
		require.Len(ev.Attributes, 1, "each event should have a single attribute")

		switch string(ev.Attributes[0].Key) {
		case "add_escrow":
			var v staking.AddEscrowEvent
			err = cbor.Unmarshal(ev.Attributes[0].Value, &v)
			require.NoError(err, "malformed add escrow event")
		case "transfer":
			var v staking.TransferEvent
			err = cbor.Unmarshal(ev.Attributes[0].Value, &v)
			require.NoError(err, "malformed add escrow event")
		default:
			t.Fatalf("unexpected event key: %+v", ev.Attributes[0].Key)
		}
	}
	require.Equal("add_escrow", string(evs[0].Attributes[0].Key), "first event should be an add escrow event")
	require.Equal("transfer", string(evs[1].Attributes[0].Key), "second event should be a transfer event")
	require.Equal("add_escrow", string(evs[2].Attributes[0].Key), "second event should be an add escrow event")

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
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
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

func TestProposalDeposits(t *testing.T) {
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	// Prepare state.
	s := NewMutableState(ctx.State())
	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	pk2 := signature.NewPublicKey("bbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr2 := staking.NewAddress(pk2)

	err := s.SetAccount(ctx, addr1, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(200),
		},
	})
	require.NoError(t, err, "SetAccount")
	err = s.SetAccount(ctx, addr2, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(200),
		},
	})
	require.NoError(t, err, "SetAccount")
	err = s.SetGovernanceDeposits(ctx, quantity.NewFromUint64(0))
	require.NoError(t, err, "SetGovernanceDeposits")

	// Do governance deposits.
	err = s.TransferToGovernanceDeposits(ctx, addr1, quantity.NewFromUint64(10))
	require.NoError(t, err, "TransferToGovernanceDeposits")
	err = s.TransferToGovernanceDeposits(ctx, addr2, quantity.NewFromUint64(20))
	require.NoError(t, err, "TransferToGovernanceDeposits")

	var deposits *quantity.Quantity
	deposits, err = s.GovernanceDeposits(ctx)
	require.NoError(t, err, "GovernanceDeposits")
	require.EqualValues(t, quantity.NewFromUint64(30), deposits, "expected governance deposit should be made")

	var acc1 *staking.Account
	acc1, err = s.Account(ctx, addr1)
	require.NoError(t, err, "Account")
	require.EqualValues(t, *quantity.NewFromUint64(190), acc1.General.Balance, "expected governance deposit should be made")

	var acc2 *staking.Account
	acc2, err = s.Account(ctx, addr2)
	require.NoError(t, err, "Account")
	require.EqualValues(t, *quantity.NewFromUint64(180), acc2.General.Balance, "expected governance deposit should be made")

	// Discard pk1 deposit.
	err = s.DiscardGovernanceDeposit(ctx, quantity.NewFromUint64(10))
	require.NoError(t, err, "DiscardGovernanceDeposit")

	// Reclaim pk2 deposit.
	err = s.TransferFromGovernanceDeposits(ctx, addr2, quantity.NewFromUint64(20))
	require.NoError(t, err, "TransferFromGovernanceDeposits")

	// Ensure final ballances are correct.
	deposits, err = s.CommonPool(ctx)
	require.NoError(t, err, "CommonPool")
	require.EqualValues(t, quantity.NewFromUint64(10), deposits, "governance funds should be discarded into the common pool")

	deposits, err = s.GovernanceDeposits(ctx)
	require.NoError(t, err, "GovernanceDeposits")
	require.EqualValues(t, quantity.NewFromUint64(0), deposits, "governance deposits should be empty")

	acc1, err = s.Account(ctx, addr1)
	require.NoError(t, err, "Account")
	require.EqualValues(t, *quantity.NewFromUint64(190), acc1.General.Balance, "governance deposit should be discarded")

	acc2, err = s.Account(ctx, addr2)
	require.NoError(t, err, "Account")
	require.EqualValues(t, *quantity.NewFromUint64(200), acc2.General.Balance, "governance deposit should be reclaimed")
}

func TestTransferFromCommon(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	// Prepare state.
	s := NewMutableState(ctx.State())
	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	pk2 := signature.NewPublicKey("bbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr2 := staking.NewAddress(pk2)

	err := s.SetCommonPool(ctx, quantity.NewFromUint64(1000))
	require.NoError(err, "SetCommonPool")

	// Transfer without escrow.
	ok, err := s.TransferFromCommon(ctx, addr1, quantity.NewFromUint64(100), false)
	require.NoError(err, "TransferFromCommon without escrow")
	require.True(ok, "TransferFromCommon should succeed")

	acc1, err := s.Account(ctx, addr1)
	require.NoError(err, "Account")
	require.EqualValues(*quantity.NewFromUint64(100), acc1.General.Balance, "amount should be transferred to general balance")
	require.EqualValues(*quantity.NewFromUint64(0), acc1.Escrow.Active.Balance, "nothing should be escrowed")

	// Transfer with escrow (no delegations).
	ok, err = s.TransferFromCommon(ctx, addr2, quantity.NewFromUint64(100), true)
	require.NoError(err, "TransferFromCommon with escrow (no delegations)")
	require.True(ok, "TransferFromCommon should succeed")

	acc2, err := s.Account(ctx, addr2)
	require.NoError(err, "Account")
	require.EqualValues(*quantity.NewFromUint64(0), acc2.General.Balance, "nothing should be in general balance")
	require.EqualValues(*quantity.NewFromUint64(100), acc2.Escrow.Active.Balance, "amount should be escrowed")
	dg, err := s.Delegation(ctx, addr2, addr2)
	require.NoError(err, "Delegation")
	require.EqualValues(*quantity.NewFromUint64(100), dg.Shares, "amount should be self-delegated")

	// Transfer with escrow (existing self-delegation).
	ok, err = s.TransferFromCommon(ctx, addr2, quantity.NewFromUint64(100), true)
	require.NoError(err, "TransferFromCommon with escrow (existing self-delegation)")
	require.True(ok, "TransferFromCommon should succeed")

	acc2, err = s.Account(ctx, addr2)
	require.NoError(err, "Account")
	require.EqualValues(*quantity.NewFromUint64(0), acc2.General.Balance, "nothing should be in general balance")
	require.EqualValues(*quantity.NewFromUint64(200), acc2.Escrow.Active.Balance, "amount should be escrowed")
	dg, err = s.Delegation(ctx, addr2, addr2)
	require.NoError(err, "Delegation")
	require.EqualValues(*quantity.NewFromUint64(100), dg.Shares, "shares should stay the same")

	// Transfer with escrow (existing self-delegation and commission).
	acc2.Escrow.CommissionSchedule = staking.CommissionSchedule{
		Rates: []staking.CommissionRateStep{{
			Start: 0,
			Rate:  *quantity.NewFromUint64(20_000), // 20%
		}},
		Bounds: []staking.CommissionRateBoundStep{{
			Start:   0,
			RateMin: *quantity.NewFromUint64(0),
			RateMax: *quantity.NewFromUint64(100_000), // 100%
		}},
	}
	err = s.SetAccount(ctx, addr2, acc2)
	require.NoError(err, "SetAccount")

	ok, err = s.TransferFromCommon(ctx, addr2, quantity.NewFromUint64(100), true)
	require.NoError(err, "TransferFromCommon with escrow (existing self-delegation and commission)")
	require.True(ok, "TransferFromCommon should succeed")

	acc2, err = s.Account(ctx, addr2)
	require.NoError(err, "Account")
	require.EqualValues(*quantity.NewFromUint64(0), acc2.General.Balance, "nothing should be in general balance")
	require.EqualValues(*quantity.NewFromUint64(300), acc2.Escrow.Active.Balance, "amount should be escrowed")
	dg, err = s.Delegation(ctx, addr2, addr2)
	require.NoError(err, "Delegation")
	require.EqualValues(*quantity.NewFromUint64(107), dg.Shares, "20%% of amount should go towards increasing self-delegation")

	// Transfer with escrow (other delegations and commission).
	var dg2 staking.Delegation
	_, err = acc2.Escrow.Active.Deposit(&dg2.Shares, quantity.NewFromUint64(100), quantity.NewFromUint64(100))
	require.NoError(err, "Deposit")
	err = s.SetDelegation(ctx, addr1, addr2, &dg2)
	require.NoError(err, "SetDelegation")

	ok, err = s.TransferFromCommon(ctx, addr2, quantity.NewFromUint64(1000), true)
	require.NoError(err, "TransferFromCommon with escrow (existing delegations and commission)")
	require.True(ok, "TransferFromCommon should succeed")

	acc2, err = s.Account(ctx, addr2)
	require.NoError(err, "Account")
	require.EqualValues(*quantity.NewFromUint64(0), acc2.General.Balance, "nothing should be in general balance")
	require.EqualValues(*quantity.NewFromUint64(900), acc2.Escrow.Active.Balance, "remaining amount should be escrowed")
	dg, err = s.Delegation(ctx, addr2, addr2)
	require.NoError(err, "Delegation")
	require.EqualValues(*quantity.NewFromUint64(123), dg.Shares, "20%% of amount should go towards increasing self-delegation")

	acc1, err = s.Account(ctx, addr1)
	require.NoError(err, "Account")
	require.EqualValues(*quantity.NewFromUint64(100), acc1.General.Balance, "general balance should be unchanged")
	dg, err = s.Delegation(ctx, addr1, addr2)
	require.NoError(err, "Delegation")
	require.EqualValues(dg2.Shares, dg.Shares, "delegated amount should be unchanged")

	// There should be nothing left in the common pool.
	cp, err := s.CommonPool(ctx)
	require.NoError(err, "CommonPool")
	require.True(cp.IsZero(), "common pool should be depleted after all the transfers")

	// Transfer from empty common pool should have no effect.
	ok, err = s.TransferFromCommon(ctx, addr1, quantity.NewFromUint64(100), false)
	require.NoError(err, "TransferFromCommon from depleted common pool")
	require.False(ok, "TransferFromCommon should indicate that nothing was transferred")

	acc1, err = s.Account(ctx, addr1)
	require.NoError(err, "Account")
	require.EqualValues(*quantity.NewFromUint64(100), acc1.General.Balance, "amount should be unchanged")
	require.EqualValues(*quantity.NewFromUint64(0), acc1.Escrow.Active.Balance, "escrow amount should be unchanged")
}

func TestTransfer(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	// Prepare state.
	s := NewMutableState(ctx.State())
	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	pk2 := signature.NewPublicKey("bbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr2 := staking.NewAddress(pk2)

	initialBalance := *quantity.NewFromUint64(200)

	err := s.SetAccount(ctx, addr1, &staking.Account{
		General: staking.GeneralAccount{
			Balance: initialBalance,
		},
	})
	require.NoError(err, "SetAccount")
	err = s.SetAccount(ctx, addr2, &staking.Account{
		General: staking.GeneralAccount{
			Balance: initialBalance,
		},
	})
	require.NoError(err, "SetAccount")

	// Transfer with insufficient balance.
	err = s.Transfer(ctx, addr1, addr2, quantity.NewFromUint64(300))
	require.Error(err, "Transfer with insufficient balance")
	require.True(errors.Is(err, staking.ErrInsufficientBalance))

	a1, err := s.Account(ctx, addr1)
	require.NoError(err, "Account(addr1)")
	a2, err := s.Account(ctx, addr2)
	require.NoError(err, "Account(addr2)")
	require.EqualValues(initialBalance, a1.General.Balance, "amount in source account should not change")
	require.EqualValues(initialBalance, a2.General.Balance, "amount in destination account should not change")
	require.Empty(ctx.GetEvents(), "no events should be emitted")

	// Transfer to same address.
	err = s.Transfer(ctx, addr1, addr1, quantity.NewFromUint64(50))
	require.NoError(err, "Transfer to same address")

	a1, err = s.Account(ctx, addr1)
	require.NoError(err, "Account(addr1)")
	require.EqualValues(initialBalance, a1.General.Balance, "amount in account should not change")
	require.Empty(ctx.GetEvents(), "no events should be emitted")

	// Transfer of zero amount.
	err = s.Transfer(ctx, addr1, addr2, quantity.NewFromUint64(0))
	require.NoError(err, "Transfer")

	a1, err = s.Account(ctx, addr1)
	require.NoError(err, "Account(addr1)")
	a2, err = s.Account(ctx, addr2)
	require.NoError(err, "Account(addr2)")
	require.EqualValues(initialBalance, a1.General.Balance, "amount in source account should not change")
	require.EqualValues(initialBalance, a2.General.Balance, "amount in destination account should not change")
	require.Empty(ctx.GetEvents(), "no events should be emitted")

	// Transfer.
	err = s.Transfer(ctx, addr1, addr2, quantity.NewFromUint64(50))
	require.NoError(err, "Transfer")

	a1, err = s.Account(ctx, addr1)
	require.NoError(err, "Account(addr1)")
	a2, err = s.Account(ctx, addr2)
	require.NoError(err, "Account(addr2)")
	require.EqualValues(*quantity.NewFromUint64(150), a1.General.Balance, "amount in source account should be correct")
	require.EqualValues(*quantity.NewFromUint64(250), a2.General.Balance, "amount in destination account should be correct")
	require.Len(ctx.GetEvents(), 1, "one event should be emitted")

	var ev staking.TransferEvent
	err = ctx.DecodeTypedEvent(0, &ev)
	require.NoError(err, "DecodeTypedEvent")
	require.EqualValues(addr1, ev.From, "event should have the correct source address")
	require.EqualValues(addr2, ev.To, "event should have the correct destination address")
	require.EqualValues(*quantity.NewFromUint64(50), ev.Amount, "event should have the correct amount")
}
