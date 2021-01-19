// Package tests is a collection of staking backend implementation tests.
package tests

import (
	"context"
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
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/staking/tests/debug"
)

const recvTimeout = 5 * time.Second

// stakingTestsState holds the current state of staking tests.
type stakingTestsState struct {
	totalSupply *quantity.Quantity
	commonPool  *quantity.Quantity

	srcAccountGeneralBalance      quantity.Quantity
	srcAccountNonce               uint64
	srcAccountEscrowActiveBalance quantity.Quantity
	srcAccountEscrowActiveShares  quantity.Quantity

	destAccountGeneralBalance quantity.Quantity
}

func (s *stakingTestsState) update(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "update: TotalSupply")
	s.totalSupply = totalSupply

	commonPool, err := backend.CommonPool(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "update: CommonPool")
	s.commonPool = commonPool

	srcAccount, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "update: src: Account")
	s.srcAccountGeneralBalance = srcAccount.General.Balance
	s.srcAccountNonce = srcAccount.General.Nonce
	s.srcAccountEscrowActiveBalance = srcAccount.Escrow.Active.Balance
	s.srcAccountEscrowActiveShares = srcAccount.Escrow.Active.TotalShares

	destAccount, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: DestAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "update: dest: Account")
	s.destAccountGeneralBalance = destAccount.General.Balance
}

func newStakingTestsState(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) (state *stakingTestsState) {
	state = &stakingTestsState{}
	state.update(t, backend, consensus)
	return
}

var (
	debugGenesisState = debug.GenesisState()

	qtyOne = *quantity.NewFromUint64(1)

	SrcSigner  = debug.DebugStateSrcSigner
	SrcAddr    = debug.DebugStateSrcAddress
	destSigner = debug.DebugStateDestSigner
	DestAddr   = debug.DebugStateDestAddress
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
		api.KindNodeStorage,
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

func testTransfer(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	dstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: DestAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dest: Account")

	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - before")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	xfer := &api.Transfer{
		To:     DestAddr,
		Amount: *quantity.NewFromUint64(math.MaxUint8),
	}
	tx := api.NewTransferTx(srcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
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
				require.Equal(SrcAddr, te.From, "Event: from")
				require.Equal(DestAddr, te.To, "Event: to")
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

	_ = srcAcc.General.Balance.Sub(&xfer.Amount)
	newSrcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	_ = dstAcc.General.Balance.Add(&xfer.Amount)
	newDstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: DestAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dest: Account - after")
	require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dest: general balance - after")
	require.EqualValues(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dest: nonce - after")

	// Transfers that exceed available balance should fail.
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Amount = newSrcAcc.General.Balance

	tx = api.NewTransferTx(newSrcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.Error(err, "Transfer - more than available balance")
}

func testSelfTransfer(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - before")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	xfer := &api.Transfer{
		To:     SrcAddr,
		Amount: *quantity.NewFromUint64(math.MaxUint8),
	}
	tx := api.NewTransferTx(srcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
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
				require.Equal(SrcAddr, te.From, "Event: from")
				require.Equal(SrcAddr, te.To, "Event: to")
				require.Equal(xfer.Amount, te.Amount, "Event: amount")
				gotTransfer = true
			}

			if gotTransfer {
				break TransferWaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive transfer event")
		}
	}

	newSrcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	// Self transfers that are more than the balance should fail.
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Amount = newSrcAcc.General.Balance

	tx = api.NewTransferTx(newSrcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.Error(err, "Transfer - more than available balance")
}

func testBurn(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "TotalSupply - before")

	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	burn := &api.Burn{
		Amount: *quantity.NewFromUint64(math.MaxUint32),
	}
	tx := api.NewBurnTx(srcAcc.General.Nonce, nil, burn)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.NoError(err, "Burn")

	select {
	case ev := <-ch:
		if ev.Burn == nil {
			t.Fatalf("expected burn event, got: %+v", ev)
		}
		be := ev.Burn

		require.Equal(SrcAddr, be.Owner, "Event: owner")
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

	_ = srcAcc.General.Balance.Sub(&burn.Amount)
	newSrcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.EqualValues(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")
}

func testEscrow(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testEscrowEx(t, state, backend, consensus, SrcAddr, SrcSigner, DestAddr)
}

func testSelfEscrow(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testEscrowEx(t, state, backend, consensus, SrcAddr, SrcSigner, SrcAddr)
}

func testEscrowEx( // nolint: gocyclo
	t *testing.T,
	state *stakingTestsState,
	backend api.Backend,
	consensus consensusAPI.Backend,
	srcAddr api.Address,
	SrcSigner signature.Signer,
	dstAddr api.Address,
) {
	require := require.New(t)

	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - before")
	require.False(srcAcc.General.Balance.IsZero(), "src: general balance != 0")
	require.Equal(state.srcAccountEscrowActiveBalance, srcAcc.Escrow.Active.Balance, "src: active escrow balance")
	require.Equal(state.srcAccountEscrowActiveShares, srcAcc.Escrow.Active.TotalShares, "src: active escrow total shares")
	require.True(srcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0")
	require.True(srcAcc.Escrow.Debonding.TotalShares.IsZero(), "src: debonding escrow total shares == 0")

	dstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: dstAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: Account - before")
	if !srcAddr.Equal(dstAddr) {
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
	escrow := &api.Escrow{
		Account: dstAddr,
		Amount:  *quantity.NewFromUint64(math.MaxUint32),
	}
	tx := api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.NoError(err, "AddEscrow")
	require.NoError(totalEscrowed.Add(&escrow.Amount))

	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.Add == nil {
			t.Fatalf("expected add escrow event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.Add
		require.NotNil(ev)
		require.Equal(srcAddr, ev.Owner, "Event: owner")
		require.Equal(dstAddr, ev.Escrow, "Event: escrow")
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
	_ = dstAcc.Escrow.Active.Deposit(currentTotalShares, &srcAcc.General.Balance, &escrow.Amount)

	newSrcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	if !srcAddr.Equal(dstAddr) {
		require.Equal(state.srcAccountEscrowActiveBalance, newSrcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after")
		require.True(newSrcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	newDstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: dstAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: Account - after")
	if !srcAddr.Equal(dstAddr) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after")
	}
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.Balance, "dst: active escrow balance - after")
	require.Equal(dstAcc.Escrow.Active.TotalShares, newDstAcc.Escrow.Active.TotalShares, "dst: active escrow total shares - after")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after")

	srcAcc = newSrcAcc
	dstAcc = newDstAcc
	newSrcAcc = nil
	newDstAcc = nil

	// Escrow some more.
	escrow = &api.Escrow{
		Account: dstAddr,
		Amount:  *quantity.NewFromUint64(math.MaxUint32),
	}
	tx = api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.NoError(err, "AddEscrow")
	require.NoError(totalEscrowed.Add(&escrow.Amount))

	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.Add == nil {
			t.Fatalf("expected add escrow event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.Add
		require.NotNil(ev)
		require.Equal(srcAddr, ev.Owner, "Event: owner")
		require.Equal(dstAddr, ev.Escrow, "Event: escrow")
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
	_ = dstAcc.Escrow.Active.Deposit(currentTotalShares, &srcAcc.General.Balance, &escrow.Amount)

	newSrcAcc, err = backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after 2nd")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after 2nd")
	if !srcAddr.Equal(dstAddr) {
		require.Equal(state.srcAccountEscrowActiveBalance, newSrcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after 2nd")
		require.True(newSrcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after 2nd")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after 2nd")

	newDstAcc, err = backend.Account(context.Background(), &api.OwnerQuery{Owner: dstAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: Account - after 2nd")
	if !srcAddr.Equal(dstAddr) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after 2nd")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after 2nd")
	}
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.Balance, "dst: active escrow balance - after 2nd")
	require.Equal(dstAcc.Escrow.Active.TotalShares, newDstAcc.Escrow.Active.TotalShares, "dst: active escrow total shares - after 2nd")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after 2nd")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after 2nd")

	srcAcc = newSrcAcc
	dstAcc = newDstAcc
	newSrcAcc = nil
	newDstAcc = nil

	// Reclaim escrow (subject to debonding).
	debs, err := backend.DebondingDelegations(context.Background(), &api.OwnerQuery{Owner: srcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - before")
	require.Len(debs, 0, "no debonding delegations before reclaiming escrow")

	reclaim := &api.ReclaimEscrow{
		Account: dstAddr,
		Shares:  dstAcc.Escrow.Active.TotalShares,
	}
	tx = api.NewReclaimEscrowTx(srcAcc.General.Nonce, nil, reclaim)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.NoError(err, "ReclaimEscrow")

	// Query debonding delegations.
	debs, err = backend.DebondingDelegations(context.Background(), &api.OwnerQuery{Owner: srcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - after (in debonding)")
	require.Len(debs, 1, "one debonding delegation after reclaiming escrow")
	require.Len(debs[dstAddr], 1, "one debonding delegation after reclaiming escrow")

	// Advance epoch to trigger debonding.
	timeSource := consensus.Beacon().(beacon.SetableBackend)
	beaconTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for debonding period to pass.
	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.Reclaim == nil {
			t.Fatalf("expected reclaim escrow event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.Reclaim
		require.NotNil(ev)
		require.Equal(srcAddr, ev.Owner, "Event: owner")
		require.Equal(dstAddr, ev.Escrow, "Event: escrow")
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
	newSrcAcc, err = backend.Account(context.Background(), &api.OwnerQuery{Owner: srcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - after debond")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after debond")
	if !srcAddr.Equal(dstAddr) {
		require.Equal(state.srcAccountEscrowActiveBalance, srcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after debond")
		require.True(srcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after debond")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after debond")

	newDstAcc, err = backend.Account(context.Background(), &api.OwnerQuery{Owner: dstAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: Account - after debond")
	if !srcAddr.Equal(dstAddr) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after debond")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after debond")
	}
	require.True(newDstAcc.Escrow.Active.Balance.IsZero(), "dst: active escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.Active.TotalShares.IsZero(), "dst: active escrow total shares == 0 - after debond")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after debond")

	debs, err = backend.DebondingDelegations(context.Background(), &api.OwnerQuery{Owner: srcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - after (debonding completed)")
	require.Len(debs, 0, "no debonding delegations after debonding has completed")

	// Reclaim escrow (without enough shares).
	reclaim = &api.ReclaimEscrow{
		Account: dstAddr,
		Shares:  reclaim.Shares,
	}
	tx = api.NewReclaimEscrowTx(newSrcAcc.General.Nonce, nil, reclaim)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.Error(err, "ReclaimEscrow")

	debs, err = backend.DebondingDelegations(context.Background(), &api.OwnerQuery{Owner: srcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations")
	require.Len(debs, 0, "no debonding delegations after failed reclaim")

	// Escrow less than the minimum amount.
	escrow = &api.Escrow{
		Account: dstAddr,
		Amount:  *quantity.NewFromUint64(1), // Minimum is 10.
	}
	tx = api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.Error(err, "AddEscrow")
}

func testAllowance(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	dstAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: DestAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dest: Account")

	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: Account - before")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	allow := &api.Allow{
		Beneficiary:  DestAddr,
		AmountChange: *quantity.NewFromUint64(math.MaxUint8),
	}
	tx := api.NewAllowTx(srcAcc.General.Nonce, nil, allow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
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

			require.Equal(SrcAddr, ac.Owner, "Event: owner")
			require.Equal(DestAddr, ac.Beneficiary, "Event: beneficiary")
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
		Owner:       SrcAddr,
		Beneficiary: DestAddr,
		Height:      consensusAPI.HeightLatest,
	})
	require.NoError(err, "Allowance")
	require.Equal(expectedNewAllowance, *newAllowance, "Allowance should return the correct value")

	// Withdraw half the amount.
	withdraw := &api.Withdraw{
		From:   SrcAddr,
		Amount: *quantity.NewFromUint64(math.MaxUint8 / 2),
	}
	tx = api.NewWithdrawTx(dstAcc.General.Nonce, nil, withdraw)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, destSigner, tx)
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

				require.Equal(SrcAddr, ac.Owner, "Event: owner")
				require.Equal(DestAddr, ac.Beneficiary, "Event: beneficiary")
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

				require.Equal(SrcAddr, te.From, "Event: from")
				require.Equal(DestAddr, te.To, "Event: to")
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
		Owner:       SrcAddr,
		Beneficiary: DestAddr,
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
	require := require.New(t)

	// Delegate some stake to the validator so we can check if slashing works.
	srcAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: SrcAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "Account")

	ch, sub, err := backend.WatchEvents(context.Background())
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	entAddr := api.NewAddress(ent.ID)

	escrow := &api.Escrow{
		Account: entAddr,
		Amount:  *quantity.NewFromUint64(math.MaxUint32),
	}
	tx := api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, SrcSigner, tx)
	require.NoError(err, "AddEscrow")

	// Query updated validator account state.
	entAcc, err := backend.Account(context.Background(), &api.OwnerQuery{Owner: entAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "Account")

	select {
	case rawEv := <-ch:
		if rawEv.Escrow == nil || rawEv.Escrow.Add == nil {
			t.Fatalf("expected add escrow event, got: %+v", rawEv)
		}

		ev := rawEv.Escrow.Add
		require.NotNil(ev)
		require.Equal(SrcAddr, ev.Owner, "Event: owner")
		require.Equal(entAddr, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Amount, ev.Amount, "Event: amount")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	// Subscribe to roothash blocks.
	blocksCh, blocksSub, err := consensus.RootHash().WatchBlocks(runtimeID)
	require.NoError(err, "WatchBlocks")
	defer blocksSub.Close()

	// Broadcast evidence. This is Tendermint-specific, if we ever have more than one
	// consensus backend, we need to change this part.
	blk, err := consensus.GetBlock(context.Background(), 1)
	require.NoError(err, "GetBlock")
	err = consensus.SubmitEvidence(context.Background(), tendermintTests.MakeConsensusEquivocationEvidence(t, ident, blk))
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

	// Make sure the node is frozen.
	nodeStatus, err := consensus.Registry().GetNodeStatus(context.Background(), &registry.IDQuery{ID: ident.NodeSigner.Public(), Height: consensusAPI.HeightLatest})
	require.NoError(err, "GetNodeStatus")
	require.False(nodeStatus.ExpirationProcessed, "ExpirationProcessed should be false")
	require.True(nodeStatus.IsFrozen(), "IsFrozen() should return true")

	// Make sure node cannot be unfrozen.
	tx = registry.NewUnfreezeNodeTx(0, nil, &registry.UnfreezeNode{
		NodeID: ident.NodeSigner.Public(),
	})
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, entSigner, tx)
	require.Error(err, "UnfreezeNode should fail")

	// Wait for roothash block as re-scheduling must have taken place due to slashing.
	select {
	case blk := <-blocksCh:
		require.Equal(block.EpochTransition, blk.Block.Header.HeaderType)
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive roothash block")
	}

	// Advance epoch to make the freeze period expire.
	timeSource := consensus.Beacon().(beacon.SetableBackend)
	beaconTests.MustAdvanceEpoch(t, timeSource, 1)

	// Unfreeze node (now it should work).
	tx = registry.NewUnfreezeNodeTx(0, nil, &registry.UnfreezeNode{
		NodeID: ident.NodeSigner.Public(),
	})
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, entSigner, tx)
	require.NoError(err, "UnfreezeNode")

	// Advance epoch to restore committees.
	beaconTests.MustAdvanceEpoch(t, timeSource, 1)

	// Make sure the node is no longer frozen.
	nodeStatus, err = consensus.Registry().GetNodeStatus(context.Background(), &registry.IDQuery{ID: ident.NodeSigner.Public(), Height: consensusAPI.HeightLatest})
	require.NoError(err, "GetNodeStatus")
	require.False(nodeStatus.ExpirationProcessed, "ExpirationProcessed should be false")
	require.False(nodeStatus.IsFrozen(), "IsFrozen() should return false")
}
