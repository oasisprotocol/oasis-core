// Package tests is a collection of staking backend implementation tests.
package tests

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tendermintTests "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/tests"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

const recvTimeout = 5 * time.Second

// accountData holds information and additional data about a staking account.
type accountData struct {
	account

	generalBalance         quantity.Quantity
	nonce                  uint64
	escrowActiveBalance    quantity.Quantity
	escrowActiveShares     quantity.Quantity
	escrowDebondingBalance quantity.Quantity
	escrowDebondingShares  quantity.Quantity
}

// update updates additional data about a staking account or returns a testing
// error.
func (a *accountData) update(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	require.NotNil(a.Address, "accountData update: address must be defined")
	acc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: a.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "accountData update: obtaining account should not fail")
	a.generalBalance = acc.General.Balance
	a.nonce = acc.General.Nonce
	a.escrowActiveBalance = acc.Escrow.Active.Balance
	a.escrowActiveShares = acc.Escrow.Active.TotalShares
	a.escrowDebondingBalance = acc.Escrow.Debonding.Balance
	a.escrowDebondingShares = acc.Escrow.Debonding.TotalShares
}

// accountDataList holds information and additional data about a list of
// staking accounts.
type accountDataList []accountData

// GetAddress returns the address of the i-th accountData in the list or panics.
//
// NOTE: Indexing is 1-based, NOT 0-based.
func (a accountDataList) GetAddress(index int) api.Address {
	i := index - 1
	if i < 0 || i >= len(a) {
		panic(fmt.Sprintf("Account with index: %d doesn't exist", index))
	}
	return a[i].Address
}

// getAccount returns the i-th accountData in the list or panics.
//
// NOTE: Indexing is 1-based, NOT 0-based.
func (a accountDataList) getAccount(index int) accountData {
	i := index - 1
	if i < 0 || i >= len(a) {
		panic(fmt.Sprintf("Account with index: %d doesn't exist", index))
	}
	return a[i]
}

// update updates the i-th accountData in the list or panics.
//
// NOTE: Indexing is 1-based, NOT 0-based.
func (a accountDataList) update(index int, t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	i := index - 1
	if i < 0 || i >= len(a) {
		panic(fmt.Sprintf("Account with index: %d doesn't exist", index))
	}
	a[i].update(t, backend, consensus)
}

// stakingTestsState holds the current state of staking tests.
type stakingTestsState struct {
	totalSupply *quantity.Quantity
	commonPool  *quantity.Quantity

	accounts accountDataList
}

// update updates staking tests' state or returns a testing error.
func (s *stakingTestsState) update(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "update: TotalSupply")
	s.totalSupply = totalSupply

	commonPool, err := backend.CommonPool(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "update: CommonPool")
	s.commonPool = commonPool

	for i := 1; i <= NumAccounts; i++ {
		s.accounts.update(i, t, backend, consensus)
	}
}

// newStakingTestsState returns a new staking tests' state or returns a testing
// error.
func newStakingTestsState(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) (state *stakingTestsState) {
	state = &stakingTestsState{}
	accountDataList := make([]accountData, NumAccounts)
	for i := 0; i < NumAccounts; i++ {
		accountDataList[i] = accountData{
			account: Accounts.getAccount(i + 1),
		}
	}
	state.accounts = accountDataList
	state.update(t, backend, consensus)
	return
}

var (
	debugGenesisState = GenesisState()

	qtyOne = *quantity.NewFromUint64(1)
)

// StakingImplementationTests exercises the basic functionality of a staking
// backend.
func StakingImplementationTests(
	t *testing.T,
	backend api.Backend,
	consensus consensusAPI.Backend,
	identity *identity.Identity,
	entity *entity.Entity,
	entitySigner signature.Signer,
	runtimeID common.Namespace,
) {
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, *stakingTestsState, api.Backend, consensusAPI.Backend)
	}{
		{"Thresholds", testThresholds},
		{"CommonPool", testCommonPool},
		{"LastBlockFees", testLastBlockFees},
		{"GovernanceDeposits", testGovernanceDeposits},
		{"Delegations", testDelegations},
		{"Transfer", testTransfer},
		{"TransferSelf", testSelfTransfer},
		{"Burn", testBurn},
		{"Escrow", testEscrow},
		{"EscrowSelf", testSelfEscrow},
		{"Allowance", testAllowance},
	} {
		state := newStakingTestsState(t, backend, consensus)
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, state, backend, consensus) })
	}

	// Separate test as it requires some arguments that others don't.
	t.Run("SlashConsensusEquivocation", func(t *testing.T) {
		state := newStakingTestsState(t, backend, consensus)
		testSlashConsensusEquivocation(t, state, backend, consensus, identity, entity, entitySigner, runtimeID)
	})
}

// StakingClientImplementationTests exercises the basic functionality of a
// staking client backend.
func StakingClientImplementationTests(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, *stakingTestsState, api.Backend, consensusAPI.Backend)
	}{
		{"Thresholds", testThresholds},
		{"LastBlockFees", testLastBlockFees},
		{"Delegations", testDelegations},
		{"Transfer", testTransfer},
		{"TransferSelf", testSelfTransfer},
		{"Burn", testBurn},
		{"Escrow", testEscrow},
		{"EscrowSelf", testSelfEscrow},
		{"Allowance", testAllowance},
	} {
		state := newStakingTestsState(t, backend, consensus)
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, state, backend, consensus) })
	}
}

func testThresholds(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	for _, kind := range []api.ThresholdKind{
		api.KindNodeValidator,
		api.KindNodeCompute,
		api.KindNodeKeyManager,
		api.KindRuntimeCompute,
		api.KindRuntimeKeyManager,
	} {
		qty, err := backend.Threshold(context.Background(), &api.ThresholdQuery{Kind: kind, Height: consensusAPI.HeightLatest})
		require.NoError(err, "Threshold")
		require.NotNil(qty, "Threshold != nil")
		require.Equal(debugGenesisState.Parameters.Thresholds[kind], *qty, "Threshold - value")
	}
}

func testCommonPool(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	commonPool, err := backend.CommonPool(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "CommonPool")

	commonPoolAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Height: consensusAPI.HeightLatest, Owner: api.CommonPoolAddress})
	require.NoError(err, "Account - CommonPool")
	require.EqualValues(commonPool, &commonPoolAcc.General.Balance, "CommonPool Account - initial value should match")
}

func testLastBlockFees(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	lastBlockFees, err := backend.LastBlockFees(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "LastBlockFees")
	require.True(lastBlockFees.IsZero(), "LastBlockFees - initial value")

	lastBlockFeesAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Height: consensusAPI.HeightLatest, Owner: api.FeeAccumulatorAddress})
	require.NoError(err, "Account - LastBlockFees")
	require.True(lastBlockFeesAcc.General.Balance.IsZero(), "LastBlockFees Account - initial value")
}

func testGovernanceDeposits(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	governanceDeposits, err := backend.GovernanceDeposits(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GovernanceDeposits")
	require.True(governanceDeposits.IsZero(), "GovernanceDeposits - initial value")

	governanceDepositsAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Height: consensusAPI.HeightLatest, Owner: api.GovernanceDepositsAddress})
	require.NoError(err, "Account - GovernanceDeposits")
	require.True(governanceDepositsAcc.General.Balance.IsZero(), "GovernaceDeposits Account - initial value")
}

func testDelegations(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	accts := state.accounts

	// Incoming delegations to accounts.
	//
	// NOTE: testEscrow/testSelfEscrow tests reclaim all active shares from
	// account 1's escrow, so we omit accout 1 from these checks.
	expectedDelegationsTo := map[int][]int{
		// Delegations to account 1.
		1: {1},
		// Delegations to account 2.
		2: {},
		// Delegations to account 3.
		3: {2, 5},
		// Delegations to account 4.
		4: {2, 3, 5, 6},
		// Delegations to account 5.
		5: {},
		// Delegations to account 6.
		6: {},
		// Delegations to account 7.
		7: {1, 5, 7},
	}

	for a := 2; a <= 7; a++ {
		delegationsToAcc, err := backend.DelegationsTo(
			context.Background(), &api.OwnerQuery{Owner: accts.GetAddress(a), Height: consensusAPI.HeightLatest},
		)
		require.NoErrorf(err, "account %d - DelegationsTo", a)
		require.Lenf(delegationsToAcc, len(expectedDelegationsTo[a]), "account %d  - number of incoming delegations", a)
		for _, i := range expectedDelegationsTo[a] {
			require.Containsf(delegationsToAcc, accts.GetAddress(i), "account %d - expected delegation from account %d", a, i)
		}
	}

	// Incoming debonding delegations to accounts.
	expectedDebDelegationsTo := map[int]map[int]int{
		// Debonding delegations to account 1.
		1: {},
		// Debonding delegations to account 2.
		2: {},
		// Debonding delegations to account 3.
		3: {
			// 2 debonding delegations from account 2.
			2: 2,
			// 1 debonding delegation from account 1.
			5: 1,
		},
		// Debonding delegations to account 4.
		4: {
			// 1 debonding delegation from account 3.
			3: 1,
			// 2 debonding delegations from account 4.
			4: 2,
			// 4 debonding delegations from account 6.
			6: 4,
			// 3 debonding delegations from account 7.
			7: 3,
		},
		// Debonding delegations to account 5.
		5: {},
		// Debonding delegations to account 6.
		6: {},
		// Debonding delegations to account 7.
		7: {
			// 1 debonding delegation from account 3.
			3: 1,
			// 2 debonding delegations from account 6.
			6: 2,
		},
	}

	for a := 1; a <= 7; a++ {
		debDelegationsToAcc, err := backend.DebondingDelegationsTo(
			context.Background(), &api.OwnerQuery{Owner: accts.GetAddress(a), Height: consensusAPI.HeightLatest},
		)
		require.NoErrorf(err, "account %d - DebondingDelegationsTo", a)
		require.Lenf(debDelegationsToAcc, len(expectedDebDelegationsTo[a]), "account %d  - number of incoming debonding delegations", a)
		for i, num := range expectedDebDelegationsTo[a] {
			require.Containsf(debDelegationsToAcc, accts.GetAddress(i), "account %d - expected debonding delegation(s) from account %d", a, i)
			require.Lenf(debDelegationsToAcc[accts.GetAddress(i)], num, "account %d - expected %d debonding delegation(s) from account %d", a, num, i)
		}
	}

	// Outgoing delegations for accounts.
	//
	// NOTE: Governance tests add a delegation from account 1 to validator's (i.e. node's) entity
	// so we omit account 1 from these checks.
	expectedDelegationsFor := map[int][]int{
		// Delegations for account 2.
		2: {3, 4},
		// Delegations for account 3.
		3: {4},
		// Delegations for account 4.
		4: {},
		// Delegations for account 5.
		5: {3, 4, 7},
		// Delegations for account 6.
		6: {4},
		// Delegations for account 7.
		7: {7},
	}
	for a := 2; a <= 7; a++ {
		delegationsForAcc, err := backend.DelegationsFor(
			context.Background(), &api.OwnerQuery{Owner: accts.GetAddress(a), Height: consensusAPI.HeightLatest},
		)
		require.NoErrorf(err, "account %d - DelegationsFor", a)
		require.Lenf(delegationsForAcc, len(expectedDelegationsFor[a]), "account %d  - number of outgoing delegations", a)
		for _, i := range expectedDelegationsFor[a] {
			require.Containsf(delegationsForAcc, accts.GetAddress(i), "account %d - expected delegation to account %d", a, i)
		}
		delegationInfosForAcc, err := backend.DelegationInfosFor(
			context.Background(), &api.OwnerQuery{Owner: accts.GetAddress(a), Height: consensusAPI.HeightLatest},
		)
		require.NoErrorf(err, "account %d - DelegationInfosFor", a)
		require.Lenf(delegationInfosForAcc, len(expectedDelegationsFor[a]), "account %d  - number of outgoing delegation infos", a)
		for _, i := range expectedDelegationsFor[a] {
			require.Containsf(delegationInfosForAcc, accts.GetAddress(i), "account %d - expected info about delegation to account %d", a, i)
			delInfo := delegationInfosForAcc[accts.GetAddress(i)]
			require.Equalf(
				accts.getAccount(i).escrowActiveBalance, delInfo.Pool.Balance,
				"account %d - info about delegation to account %d: pool balance doesn't match", a, i,
			)
			require.Equalf(
				accts.getAccount(i).escrowActiveShares, delInfo.Pool.TotalShares,
				"account %d - info about delegation to account %d: pool shares don't match", a, i,
			)
		}
	}

	// Outgoing debonding delegations for accounts.
	expectedDebDelegationsFor := map[int]map[int]int{
		// Debonding delegations for account 1.
		1: {},
		// Debonding delegations for account 2.
		2: {
			// 2 debonding delegations to account 3.
			3: 2,
		},
		// Debonding delegations for account 3.
		3: {
			// 1 debonding delegation to account 4.
			4: 1,
			// 1 debonding delegation to account 7.
			7: 1,
		},
		// Debonding delegations for account 4.
		4: {
			// 2 debonding delegations to account 4.
			4: 2,
		},
		// Debonding delegations for account 5.
		5: {
			// 1 debonding delegation to account 3.
			3: 1,
		},
		// Debonding delegations for account 6.
		6: {
			// 4 debonding delegations to account 4.
			4: 4,
			// 2 debonding delegations to account 7.
			7: 2,
		},
		// Debonding delegations for account 7.
		7: {
			// 3 debonding delegations to account 4.
			4: 3,
		},
	}

	for a := 1; a <= 7; a++ {
		debDelegationsForAcc, err := backend.DebondingDelegationsFor(
			context.Background(), &api.OwnerQuery{Owner: accts.GetAddress(a), Height: consensusAPI.HeightLatest},
		)
		require.NoErrorf(err, "account %d - DebondingDelegationsFor", a)
		require.Lenf(debDelegationsForAcc, len(expectedDebDelegationsFor[a]), "account %d  - number of outgoing debonding delegations", a)
		for i, num := range expectedDebDelegationsFor[a] {
			require.Containsf(debDelegationsForAcc, accts.GetAddress(i), "account %d - expected debonding delegation(s) to account %d", a, i)
			require.Lenf(debDelegationsForAcc[accts.GetAddress(i)], num, "account %d - expected %d debonding delegation(s) to account %d", a, num, i)
		}
		debDelegationInfosForAcc, err := backend.DebondingDelegationInfosFor(
			context.Background(), &api.OwnerQuery{Owner: accts.GetAddress(a), Height: consensusAPI.HeightLatest},
		)
		require.NoErrorf(err, "account %d - DebondingDelegationInfosFor", a)
		require.Lenf(debDelegationInfosForAcc, len(expectedDebDelegationsFor[a]), "account %d  - number of outgoing debonding delegation infos", a)
		for i, num := range expectedDebDelegationsFor[a] {
			require.Containsf(
				debDelegationInfosForAcc, accts.GetAddress(i),
				"account %d - expected info about debonding delegation(s) to account %d", a, i,
			)
			debDelInfos := debDelegationInfosForAcc[accts.GetAddress(i)]
			require.Lenf(debDelInfos, num, "account %d - expected %d debonding delegation(s) to account %d", a, num, i)
			for j, debDelInfo := range debDelInfos {
				require.Equalf(
					accts.getAccount(i).escrowDebondingBalance, debDelInfo.Pool.Balance,
					"account %d - info about debonding delegation %d to account %d: pool balance doesn't match", a, j, i,
				)
				require.Equalf(
					accts.getAccount(i).escrowDebondingShares, debDelInfo.Pool.TotalShares,
					"account %d - info about debonding delegation %d to account %d: pool shares don't match", a, j, i,
				)
			}
		}
	}
}

func testTransfer(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testTransferHelper(t, state, backend, consensus, state.accounts.getAccount(1), state.accounts.getAccount(2))
}

func testSelfTransfer(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testTransferHelper(t, state, backend, consensus, state.accounts.getAccount(1), state.accounts.getAccount(1))
}

func testTransferHelper(
	t *testing.T,
	state *stakingTestsState,
	backend api.Backend,
	consensus consensusAPI.Backend,
	srcAccData, destAccData accountData,
) {
	require := require.New(t)

	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - before")

	dstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: destAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dest: Account")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	xfer := &api.Transfer{
		To:     destAccData.Address,
		Amount: *quantity.NewFromUint64(math.MaxUint8),
	}
	tx := api.NewTransferTx(srcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcAccData.Signer, tx)
	require.NoError(err, "Transfer")

	var gotTransfer bool

TransferWaitLoop:
	for {
		select {
		case ev := <-ch:
			if ev.Transfer == nil {
				continue
			}
			te := ev.Transfer

			if te.From.Equal(api.CommonPoolAddress) || te.To.Equal(api.CommonPoolAddress) {
				require.False(te.Amount.IsZero(), "CommonPool xfer: amount should be non-zero")
				continue
			}
			if te.From.Equal(api.FeeAccumulatorAddress) || te.To.Equal(api.FeeAccumulatorAddress) {
				require.False(te.Amount.IsZero(), "FeeAccumulator xfer: amount should be non-zero")
				continue
			}

			if !gotTransfer {
				require.Equal(srcAccData.Address, te.From, "Event: from")
				require.Equal(destAccData.Address, te.To, "Event: to")
				require.Equal(xfer.Amount, te.Amount, "Event: amount")

				// Make sure that GetEvents also returns the transfer event.
				evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
				require.NoError(grr, "GetEvents")
				for _, evt := range evts {
					if evt.Transfer != nil {
						if evt.Transfer.From.Equal(te.From) && evt.Transfer.To.Equal(te.To) && evt.Transfer.Amount.Cmp(&te.Amount) == 0 {
							gotTransfer = true
							require.True(!evt.TxHash.IsEmpty(), "GetEvents should return valid txn hash")
							break
						}
					}
				}
				require.True(gotTransfer, "GetEvents should return transfer event")
			}

			if gotTransfer {
				break TransferWaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive transfer event")
		}
	}

	newSrcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after")
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")
	// Only subtract transfer amount if destination account is different from the
	// source account.
	if !srcAccData.Address.Equal(destAccData.Address) {
		_ = srcAcc.General.Balance.Sub(&xfer.Amount)
	}
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")

	// Only query destination account if it is different from the source account.
	if !srcAccData.Address.Equal(destAccData.Address) {
		newDstAcc, err2 := backend.Account(context.Background(), &api.OwnerQuery{Owner: destAccData.Address, Height: consensusAPI.HeightLatest})
		require.NoError(err2, "dest: Account - after")
		require.EqualValues(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dest: nonce - after")
		_ = dstAcc.General.Balance.Add(&xfer.Amount)
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dest: general balance - after")
	}

	// Transfers that exceed available balance should fail.
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Amount = newSrcAcc.General.Balance

	tx = api.NewTransferTx(newSrcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcAccData.Signer, tx)
	require.Error(err, "Transfer - more than available balance")
}

func testBurn(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	accData := state.accounts.getAccount(1)

	totalSupply, err := backend.TotalSupply(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "TotalSupply - before")

	acc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: accData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	amount := acc.General.Balance.Clone()
	_ = amount.Quo(quantity.NewFromUint64(2))
	burn := &api.Burn{
		Amount: *amount,
	}
	tx := api.NewBurnTx(acc.General.Nonce, nil, burn)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, accData.Signer, tx)
	require.NoError(err, "Burn")

	select {
	case ev := <-ch:
		if ev.Burn == nil {
			t.Fatalf("expected burn event, got: %+v", ev)
		}
		be := ev.Burn

		require.Equal(accData.Address, be.Owner, "Event: owner")
		require.Equal(burn.Amount, be.Amount, "Event: amount")

		// Make sure that GetEvents also returns the burn event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.Burn != nil {
				if evt.Burn.Owner.Equal(be.Owner) && evt.Burn.Amount.Cmp(&be.Amount) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return burn event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive burn event")
	}

	_ = totalSupply.Sub(&burn.Amount)
	newTotalSupply, err := backend.TotalSupply(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "TotalSupply - after")
	require.Equal(totalSupply, newTotalSupply, "totalSupply is reduced by burn")

	_ = acc.General.Balance.Sub(&burn.Amount)
	newSrcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: accData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account")
	require.Equal(acc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.EqualValues(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")
}

func testEscrow(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testEscrowHelper(t, state, backend, consensus, state.accounts.getAccount(1), state.accounts.getAccount(2))
}

func testSelfEscrow(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testEscrowHelper(t, state, backend, consensus, state.accounts.getAccount(1), state.accounts.getAccount(1))
}

func testEscrowHelper( // nolint: gocyclo
	t *testing.T,
	state *stakingTestsState,
	backend api.Backend,
	consensus consensusAPI.Backend,
	srcAccData, destAccData accountData,
) {
	require := require.New(t)

	params, err := backend.ConsensusParameters(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "stkaing.ConsensusParameters")

	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - before")
	require.False(srcAcc.General.Balance.IsZero(), "src: general balance != 0")
	require.Equal(srcAccData.escrowActiveBalance, srcAcc.Escrow.Active.Balance, "src: active escrow balance")
	require.Equal(srcAccData.escrowActiveShares, srcAcc.Escrow.Active.TotalShares, "src: active escrow total shares")
	require.True(srcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0")
	require.True(srcAcc.Escrow.Debonding.TotalShares.IsZero(), "src: debonding escrow total shares == 0")

	dstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: destAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: Account - before")
	if !srcAccData.Address.Equal(destAccData.Address) {
		require.True(dstAcc.Escrow.Active.Balance.IsZero(), "dst: active escrow balance == 0")
		require.True(dstAcc.Escrow.Active.TotalShares.IsZero(), "dst: active escrow total shares == 0")
	}
	require.True(dstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0")
	require.True(dstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	totalEscrowed := dstAcc.Escrow.Active.Balance.Clone()

	// Escrow.
	amount := srcAcc.General.Balance.Clone()
	_ = amount.Quo(quantity.NewFromUint64(2))
	escrow := &api.Escrow{
		Account: destAccData.Address,
		Amount:  *amount,
	}
	tx := api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcAccData.Signer, tx)
	require.NoError(err, "AddEscrow")
	require.NoError(totalEscrowed.Add(&escrow.Amount))

	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.Add == nil {
			t.Fatalf("expected add escrow event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.Add
		require.NotNil(ev)
		require.Equal(srcAccData.Address, ev.Owner, "Event: owner")
		require.Equal(destAccData.Address, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Amount, ev.Amount, "Event: amount")

		// Make sure that GetEvents also returns the add escrow event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.Escrow != nil && evt.Escrow.Add != nil {
				if evt.Escrow.Add.Owner.Equal(ev.Owner) && evt.Escrow.Add.Escrow.Equal(ev.Escrow) && evt.Escrow.Add.Amount.Cmp(&ev.Amount) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return add escrow event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	currentTotalShares := dstAcc.Escrow.Active.TotalShares.Clone()
	sharesBefore := dstAcc.Escrow.Active.TotalShares.Clone()
	newShares, err := dstAcc.Escrow.Active.Deposit(currentTotalShares, &srcAcc.General.Balance, &escrow.Amount)
	require.NoError(err, "src: deposit")

	newSrcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	if !srcAccData.Address.Equal(destAccData.Address) {
		require.Equal(srcAccData.escrowActiveBalance, newSrcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after")
		require.True(newSrcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	newDstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: destAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: Account - after")
	if !srcAccData.Address.Equal(destAccData.Address) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after")
	}
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.Balance, "dst: active escrow balance - after")
	require.Equal(dstAcc.Escrow.Active.TotalShares, newDstAcc.Escrow.Active.TotalShares, "dst: active escrow total shares - after")

	// Compute actually added shares.
	addedShares := dstAcc.Escrow.Active.TotalShares.Clone()
	require.NoError(addedShares.Sub(sharesBefore), "dst: totalShares.Sub(sharesBefore)")
	require.Equal(addedShares, newShares, "dst: expected amount of added shares")

	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after")

	srcAcc = newSrcAcc
	dstAcc = newDstAcc
	newSrcAcc = nil
	newDstAcc = nil

	// Escrow some more.
	amount = srcAcc.General.Balance.Clone()
	_ = amount.Quo(quantity.NewFromUint64(2))
	escrow = &api.Escrow{
		Account: destAccData.Address,
		Amount:  *amount,
	}
	tx = api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcAccData.Signer, tx)
	require.NoError(err, "AddEscrow")
	require.NoError(totalEscrowed.Add(&escrow.Amount))

	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.Add == nil {
			t.Fatalf("expected add escrow event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.Add
		require.NotNil(ev)
		require.Equal(srcAccData.Address, ev.Owner, "Event: owner")
		require.Equal(destAccData.Address, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Amount, ev.Amount, "Event: amount")

		// Make sure that GetEvents also returns the add escrow event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.Escrow != nil && evt.Escrow.Add != nil {
				if evt.Escrow.Add.Owner.Equal(ev.Owner) && evt.Escrow.Add.Escrow.Equal(ev.Escrow) && evt.Escrow.Add.Amount.Cmp(&ev.Amount) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return add escrow event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	currentTotalShares = dstAcc.Escrow.Active.TotalShares.Clone()
	sharesBefore = dstAcc.Escrow.Active.TotalShares.Clone()
	newShares, err = dstAcc.Escrow.Active.Deposit(currentTotalShares, &srcAcc.General.Balance, &escrow.Amount)
	require.NoError(err, "src: deposit - after 2nd")

	newSrcAcc, err = backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after 2nd")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after 2nd")
	if !srcAccData.Address.Equal(destAccData.Address) {
		require.Equal(srcAccData.escrowActiveBalance, newSrcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after 2nd")
		require.True(newSrcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after 2nd")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after 2nd")

	newDstAcc, err = backend.Account(context.Background(), &api.OwnerQuery{Owner: destAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: Account - after 2nd")
	if !srcAccData.Address.Equal(destAccData.Address) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after 2nd")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after 2nd")
	}
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.Balance, "dst: active escrow balance - after 2nd")
	require.Equal(dstAcc.Escrow.Active.TotalShares, newDstAcc.Escrow.Active.TotalShares, "dst: active escrow total shares - after 2nd")

	// Compute actually added shares.
	addedShares = dstAcc.Escrow.Active.TotalShares.Clone()
	require.NoError(addedShares.Sub(sharesBefore), "dst: totalShares.Sub(sharesBefore) - after 2nd")
	require.Equal(addedShares, newShares, "dst: expected amount of added shares - after 2nd")

	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after 2nd")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after 2nd")

	srcAcc = newSrcAcc
	dstAcc = newDstAcc
	newSrcAcc = nil
	newDstAcc = nil

	// Reclaim escrow (subject to debonding).
	debs, err := backend.DebondingDelegationsFor(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - before")
	require.Len(debs, 0, "no debonding delegations before reclaiming escrow")

	reclaim := &api.ReclaimEscrow{
		Account: destAccData.Address,
		Shares:  dstAcc.Escrow.Active.TotalShares,
	}
	tx = api.NewReclaimEscrowTx(srcAcc.General.Nonce, nil, reclaim)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcAccData.Signer, tx)
	require.NoError(err, "ReclaimEscrow")

	epoch, err := consensus.Beacon().GetEpoch(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	// Wait for debonding start event.
	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.DebondingStart == nil {
			t.Fatalf("expected debonding start event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.DebondingStart
		require.NotNil(ev)
		require.Equal(srcAccData.Address, ev.Owner, "Event: owner")
		require.Equal(destAccData.Address, ev.Escrow, "Event: escrow")
		require.Equal(totalEscrowed, &ev.Amount, "Event: amount")
		require.Equal(reclaim.Shares, ev.ActiveShares, "Event: active shares")
		require.Equal(totalEscrowed, &ev.DebondingShares, "Event: debonding shares") // Nothing else is debonding, so ratio is 1:1.
		require.Equal(epoch+params.DebondingInterval, ev.DebondEndTime, "Event: debond end time")

		// Make sure that GetEvents also returns the debonding start event.
		evts, grr := backend.GetEvents(context.Background(), rawEv.Height)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.Escrow != nil && evt.Escrow.DebondingStart != nil {
				if evt.Escrow.DebondingStart.Owner.Equal(ev.Owner) && evt.Escrow.DebondingStart.Escrow.Equal(ev.Escrow) && evt.Escrow.DebondingStart.Amount.Cmp(&ev.Amount) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return debonding start event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive debonding start event")
	}

	// Query debonding delegations.
	debs, err = backend.DebondingDelegationsFor(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - after (in debonding)")
	require.Len(debs, 1, "one debonding delegation after reclaiming escrow")
	require.Len(debs[destAccData.Address], 1, "one debonding delegation after reclaiming escrow")

	// Advance epoch to trigger debonding.
	timeSource := consensus.Beacon().(beacon.SetableBackend)
	beaconTests.MustAdvanceEpoch(t, timeSource)

	// Wait for debonding period to pass.
	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.Reclaim == nil {
			t.Fatalf("expected reclaim escrow event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.Reclaim
		require.NotNil(ev)
		require.Equal(srcAccData.Address, ev.Owner, "Event: owner")
		require.Equal(destAccData.Address, ev.Escrow, "Event: escrow")
		require.Equal(totalEscrowed, &ev.Amount, "Event: amount")

		// Make sure that GetEvents also returns the reclaim escrow event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.Escrow != nil && evt.Escrow.Reclaim != nil {
				if evt.Escrow.Reclaim.Owner.Equal(ev.Owner) && evt.Escrow.Reclaim.Escrow.Equal(ev.Escrow) && evt.Escrow.Reclaim.Amount.Cmp(&ev.Amount) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return reclaim escrow event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive reclaim escrow event")
	}

	_ = srcAcc.General.Balance.Add(totalEscrowed)
	newSrcAcc, err = backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after debond")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after debond")
	if !srcAccData.Address.Equal(destAccData.Address) {
		require.Equal(srcAccData.escrowActiveBalance, srcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after debond")
		require.True(srcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after debond")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after debond")

	newDstAcc, err = backend.Account(context.Background(), &api.OwnerQuery{Owner: destAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: Account - after debond")
	if !srcAccData.Address.Equal(destAccData.Address) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after debond")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after debond")
	}
	require.True(newDstAcc.Escrow.Active.Balance.IsZero(), "dst: active escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.Active.TotalShares.IsZero(), "dst: active escrow total shares == 0 - after debond")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after debond")

	debs, err = backend.DebondingDelegationsFor(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - after (debonding completed)")
	require.Len(debs, 0, "no debonding delegations after debonding has completed")

	// Reclaim escrow (without enough shares).
	reclaim = &api.ReclaimEscrow{
		Account: destAccData.Address,
		Shares:  reclaim.Shares,
	}
	tx = api.NewReclaimEscrowTx(newSrcAcc.General.Nonce, nil, reclaim)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcAccData.Signer, tx)
	require.Error(err, "ReclaimEscrow")

	debs, err = backend.DebondingDelegationsFor(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations")
	require.Len(debs, 0, "no debonding delegations after failed reclaim")

	// Escrow less than the minimum amount.
	escrow = &api.Escrow{
		Account: destAccData.Address,
		Amount:  *quantity.NewFromUint64(1), // Minimum is 10.
	}
	tx = api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcAccData.Signer, tx)
	require.Error(err, "AddEscrow")
}

func testAllowance(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testAllowanceHelper(t, state, backend, consensus, state.accounts.getAccount(1), state.accounts.getAccount(2))
}

func testAllowanceHelper(
	t *testing.T,
	state *stakingTestsState,
	backend api.Backend,
	consensus consensusAPI.Backend,
	srcAccData, destAccData accountData,
) {
	require := require.New(t)

	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - before")

	dstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: destAccData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dest: Account")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	allow := &api.Allow{
		Beneficiary:  destAccData.Address,
		AmountChange: *quantity.NewFromUint64(math.MaxUint8),
	}
	tx := api.NewAllowTx(srcAcc.General.Nonce, nil, allow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcAccData.Signer, tx)
	require.NoError(err, "Allow")

	// Compute what new the total expected allowance should be.
	expectedNewAllowance := allow.AmountChange
	if srcAcc.General.Allowances != nil {
		allowance := srcAcc.General.Allowances[allow.Beneficiary]
		_ = expectedNewAllowance.Add(&allowance)
	}

AllowWaitLoop:
	for {
		select {
		case ev := <-ch:
			if ev.AllowanceChange == nil {
				continue
			}
			ac := ev.AllowanceChange

			require.Equal(srcAccData.Address, ac.Owner, "Event: owner")
			require.Equal(destAccData.Address, ac.Beneficiary, "Event: beneficiary")
			require.Equal(expectedNewAllowance, ac.Allowance, "Event: allowance")
			require.Equal(allow.Negative, ac.Negative, "Event: negative")
			require.Equal(allow.AmountChange, ac.AmountChange, "Event: amount change")

			// Make sure that GetEvents also returns the allowance change event.
			evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
			require.NoError(grr, "GetEvents")
			for _, ev2 := range evts {
				if ev2.AllowanceChange == nil {
					continue
				}
				ac2 := ev2.AllowanceChange
				if ac2.Owner.Equal(ac.Owner) && ac2.Beneficiary.Equal(ac.Beneficiary) {
					require.EqualValues(ac, ac2, "GetEvents should return the same event")
					require.True(!ev2.TxHash.IsEmpty(), "GetEvents should return valid txn hash")
					break AllowWaitLoop
				}
			}
			t.Fatalf("GetEvents should return allowance change event")
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive allowance change event")
		}
	}

	// Verify that the new allowance is correct.
	newAllowance, err := backend.Allowance(context.Background(), &api.AllowanceQuery{
		Owner:       srcAccData.Address,
		Beneficiary: destAccData.Address,
		Height:      consensusAPI.HeightLatest,
	})
	require.NoError(err, "Allowance")
	require.Equal(expectedNewAllowance, *newAllowance, "Allowance should return the correct value")

	// Withdraw half the amount.
	withdraw := &api.Withdraw{
		From:   srcAccData.Address,
		Amount: *quantity.NewFromUint64(math.MaxUint8 / 2),
	}
	tx = api.NewWithdrawTx(dstAcc.General.Nonce, nil, withdraw)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, destAccData.Signer, tx)
	require.NoError(err, "Withdraw")

	_ = expectedNewAllowance.Sub(&withdraw.Amount)

	var (
		gotAllowanceChange bool
		gotTransfer        bool
	)
	for {
		if gotAllowanceChange && gotTransfer {
			break
		}

		select {
		case ev := <-ch:
			switch {
			case ev.AllowanceChange != nil:
				ac := ev.AllowanceChange

				require.Equal(srcAccData.Address, ac.Owner, "Event: owner")
				require.Equal(destAccData.Address, ac.Beneficiary, "Event: beneficiary")
				require.Equal(expectedNewAllowance, ac.Allowance, "Event: allowance")
				require.Equal(true, ac.Negative, "Event: negative")
				require.Equal(withdraw.Amount, ac.AmountChange, "Event: amount change")
				gotAllowanceChange = true
			case ev.Transfer != nil:
				te := ev.Transfer

				if te.From.Equal(api.CommonPoolAddress) || te.To.Equal(api.CommonPoolAddress) {
					continue
				}
				if te.From.Equal(api.FeeAccumulatorAddress) || te.To.Equal(api.FeeAccumulatorAddress) {
					continue
				}

				require.Equal(srcAccData.Address, te.From, "Event: from")
				require.Equal(destAccData.Address, te.To, "Event: to")
				require.Equal(withdraw.Amount, te.Amount, "Event: amount")
				gotTransfer = true
			default:
				continue
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive allowance change and transfer events")
		}
	}

	// Verify that the new allowance is correct.
	newAllowance, err = backend.Allowance(context.Background(), &api.AllowanceQuery{
		Owner:       srcAccData.Address,
		Beneficiary: destAccData.Address,
		Height:      consensusAPI.HeightLatest,
	})
	require.NoError(err, "Allowance")
	require.Equal(expectedNewAllowance, *newAllowance, "Allowance should return the correct value")
}

func testSlashConsensusEquivocation(
	t *testing.T,
	state *stakingTestsState,
	backend api.Backend,
	consensus consensusAPI.Backend,
	ident *identity.Identity,
	ent *entity.Entity,
	entSigner signature.Signer,
	runtimeID common.Namespace,
) {
	ctx := context.Background()
	require := require.New(t)

	accData := state.accounts.getAccount(1)

	// Delegate some stake to the test validator so we can check if slashing works.
	acc, err := backend.Account(ctx, &api.OwnerQuery{Owner: accData.Address, Height: consensusAPI.HeightLatest})
	require.NoError(err, "Account")

	ch, sub, err := backend.WatchEvents(ctx)
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	entAddr := api.NewAddress(ent.ID)

	amount := acc.General.Balance.Clone()
	_ = amount.Quo(quantity.NewFromUint64(2))
	escrow := &api.Escrow{
		Account: entAddr,
		Amount:  *amount,
	}
	tx := api.NewAddEscrowTx(acc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, accData.Signer, tx)
	require.NoError(err, "AddEscrow")

	// Query updated validator account state.
	entAcc, err := backend.Account(ctx, &api.OwnerQuery{Owner: entAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "Account")

	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.Add == nil {
			t.Fatalf("expected add escrow event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.Add
		require.NotNil(ev)
		require.Equal(accData.Address, ev.Owner, "Event: owner")
		require.Equal(entAddr, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Amount, ev.Amount, "Event: amount")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	// Subscribe to roothash blocks.
	blocksCh, blocksSub, err := consensus.RootHash().WatchBlocks(ctx, runtimeID)
	require.NoError(err, "WatchBlocks")
	defer blocksSub.Close()

	// Broadcast evidence. This is Tendermint-specific, if we ever have more than one
	// consensus backend, we need to change this part.
	blk, err := consensus.GetBlock(ctx, 1)
	require.NoError(err, "GetBlock")

	genesis, err := consensus.GetGenesisDocument(ctx)
	require.NoError(err, "GetGenesisDocument")

	evidence, err := tendermintTests.MakeConsensusEquivocationEvidence(ident, blk, genesis, 1, 1)
	require.NoError(err, "MakeConsensusEquivocationEvidence")
	err = consensus.SubmitEvidence(ctx, evidence)
	require.NoError(err, "SubmitEvidence")

	// Wait for the node to get slashed.
WaitLoop:
	for {
		select {
		case ev := <-ch:
			if ev.Escrow == nil {
				continue
			}

			if e := ev.Escrow.Take; e != nil {
				require.Equal(entAddr, e.Owner, "TakeEscrowEvent - owner must be entity's address")
				// All stake must be slashed as defined in debugGenesisState.
				require.Equal(entAcc.Escrow.Active.Balance, e.Amount, "TakeEscrowEvent - all stake slashed")
				break WaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive slash event")
		}
	}
	// XXX: no freezing is configured for this.

	// Wait for roothash block as re-scheduling must have taken place due to slashing.
	select {
	case blk := <-blocksCh:
		require.Equal(block.EpochTransition, blk.Block.Header.HeaderType)
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive roothash block")
	}
}
