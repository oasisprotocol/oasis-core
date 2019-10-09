// Pacakge tests is a collection of staking token backend implementation tests.
package tests

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
	"github.com/oasislabs/oasis-core/go/staking/api"
)

const recvTimeout = 5 * time.Second

var (
	// DebugGenesisState is the string representation of the initial
	// genesis state that the backend MUST be populated with.
	DebugGenesisState string

	debugGenesisState = api.Genesis{
		TotalSupply:       testTotalSupply,
		DebondingInterval: 1,
		Ledger: map[signature.MapKey]*api.Account{
			SrcID.ToMapKey(): &api.Account{
				General: api.GeneralAccount{
					Balance: testTotalSupply,
				},
			},
		},
		Thresholds: map[api.ThresholdKind]api.Quantity{
			api.KindEntity:    QtyFromInt(1),
			api.KindValidator: QtyFromInt(2),
			api.KindCompute:   QtyFromInt(3),
			api.KindStorage:   QtyFromInt(4),
		},
		AcceptableTransferPeers: map[signature.MapKey]bool{
			// test runtime 0 from roothash tester
			publicKeyFromHex("612b31ddd66fc99e41cc9996f4029ea84752785d7af329d4595c4bcf8f5e4215").ToMapKey(): true,
		},
	}

	testTotalSupply = QtyFromInt(math.MaxInt64)
	qtyOne          = QtyFromInt(1)

	srcSigner  = mustGenerateSigner()
	SrcID      = srcSigner.Public()
	destSigner = mustGenerateSigner()
	DestID     = destSigner.Public()
)

// StakingImplementationTests exercises the basic functionality of a
// staking token backend.
func StakingImplementationTests(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, api.Backend, epochtime.SetableBackend)
	}{
		{"InitialEnv", testInitialEnv},
		{"Transfer", testTransfer},
		{"TransferSelf", testSelfTransfer},
		{"Burn", testBurn},
		{"Escrow", testEscrow},
	} {
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, backend, timeSource) })
	}
}

func testInitialEnv(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background())
	require.NoError(err, "TotalSupply")
	require.Equal(&testTotalSupply, totalSupply, "TotalSupply - value")

	accounts, err := backend.Accounts(context.Background())
	require.NoError(err, "Accounts")
	require.Len(accounts, 1, "Accounts - nr entries")
	require.Equal(SrcID, accounts[0], "Accounts[0] == testID")

	acc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo")
	require.Equal(testTotalSupply, acc.General.Balance, "src: general balance")
	require.True(acc.Escrow.Balance.IsZero(), "src: escrow balance")
	require.EqualValues(0, acc.General.Nonce, "src: nonce")

	commonPool, err := backend.CommonPool(context.Background())
	require.NoError(err, "CommonPool")
	require.True(commonPool.IsZero(), "CommonPool - initial value")

	for _, kind := range []api.ThresholdKind{
		api.KindValidator,
		api.KindCompute,
		api.KindStorage,
	} {
		qty, err := backend.Threshold(context.Background(), kind)
		require.NoError(err, "Threshold")
		require.NotNil(qty, "Threshold != nil")
		require.Equal(debugGenesisState.Thresholds[kind], *qty, "Threshold - value")
	}
}

func testTransfer(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	dstAcc, err := backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "dest: AccountInfo")
	require.True(dstAcc.General.Balance.IsZero(), "dest: general balance - before")
	require.EqualValues(0, dstAcc.General.Nonce, "dest: nonce - before")

	srcAcc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - before")

	ch, sub := backend.WatchTransfers()
	defer sub.Close()

	xfer := &api.Transfer{
		Nonce:  srcAcc.General.Nonce,
		To:     DestID,
		Tokens: QtyFromInt(math.MaxUint8),
	}
	signed, err := api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer")

	err = backend.Transfer(context.Background(), signed)
	require.NoError(err, "Transfer")

	select {
	case ev := <-ch:
		require.Equal(SrcID, ev.From, "Event: from")
		require.Equal(DestID, ev.To, "Event: to")
		require.Equal(xfer.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive transfer event")
	}

	_ = srcAcc.General.Balance.Sub(&xfer.Tokens)
	newSrcAcc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.Equal(xfer.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	dstAcc, err = backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "dest: AccountInfo - after")
	require.Equal(xfer.Tokens, dstAcc.General.Balance, "dest: general balance - after")
	require.EqualValues(0, dstAcc.General.Nonce, "dest: nonce - after")

	// Transfers that exceed available balance should fail.
	xfer.Nonce = newSrcAcc.General.Nonce
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Tokens = newSrcAcc.General.Balance

	signed, err = api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer - fail test")

	err = backend.Transfer(context.Background(), signed)
	require.Error(err, "Transfer - more than available balance")
}

func testSelfTransfer(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	srcAcc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - before")

	ch, sub := backend.WatchTransfers()
	defer sub.Close()

	xfer := &api.Transfer{
		Nonce:  srcAcc.General.Nonce,
		To:     SrcID,
		Tokens: QtyFromInt(math.MaxUint8),
	}
	signed, err := api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer")

	err = backend.Transfer(context.Background(), signed)
	require.NoError(err, "Transfer")

	select {
	case ev := <-ch:
		require.Equal(SrcID, ev.From, "Event: from")
		require.Equal(SrcID, ev.To, "Event: to")
		require.Equal(xfer.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive transfer event")
	}

	newSrcAcc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.Equal(xfer.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	// Self transfers that are more than the balance should fail.
	xfer.Nonce = newSrcAcc.General.Nonce
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Tokens = newSrcAcc.General.Balance

	signed, err = api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer - fail test")

	err = backend.Transfer(context.Background(), signed)
	require.Error(err, "Transfer - more than available balance")
}

func testBurn(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background())
	require.NoError(err, "TotalSupply - before")

	srcAcc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo")

	ch, sub := backend.WatchBurns()
	defer sub.Close()

	burn := &api.Burn{
		Nonce:  srcAcc.General.Nonce,
		Tokens: QtyFromInt(math.MaxUint32),
	}
	signed, err := api.SignBurn(srcSigner, burn)
	require.NoError(err, "Sign burn")

	err = backend.Burn(context.Background(), signed)
	require.NoError(err, "Burn")

	select {
	case ev := <-ch:
		require.Equal(SrcID, ev.Owner, "Event: owner")
		require.Equal(burn.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive burn event")
	}

	_ = totalSupply.Sub(&burn.Tokens)
	newTotalSupply, err := backend.TotalSupply(context.Background())
	require.NoError(err, "TotalSupply - after")
	require.Equal(totalSupply, newTotalSupply, "totalSupply is reduced by burn")

	_ = srcAcc.General.Balance.Sub(&burn.Tokens)
	newSrcAcc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.EqualValues(burn.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")
}

func testEscrow(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	srcAcc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - before")
	require.False(srcAcc.General.Balance.IsZero(), "src: general balance != 0")
	require.True(srcAcc.Escrow.Balance.IsZero(), "src: escrow balance == 0")

	dstAcc, err := backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "dst: AccountInfo - before")
	require.True(dstAcc.Escrow.Balance.IsZero(), "dst: escrow balance == 0")
	require.True(dstAcc.Escrow.TotalShares.IsZero(), "dst: escrow total shares == 0")
	require.True(dstAcc.Escrow.DebondingShares.IsZero(), "dst: escrow debonding shares == 0")

	ch, sub := backend.WatchEscrows()
	defer sub.Close()

	// Escrow.
	escrow := &api.Escrow{
		Nonce:   srcAcc.General.Nonce,
		Account: DestID,
		Tokens:  QtyFromInt(math.MaxUint32),
	}
	signed, err := api.SignEscrow(srcSigner, escrow)
	require.NoError(err, "Sign escrow")

	err = backend.AddEscrow(context.Background(), signed)
	require.NoError(err, "AddEscrow")

	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.EscrowEvent)
		require.Equal(SrcID, ev.Owner, "Event: owner")
		require.Equal(DestID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	_ = srcAcc.General.Balance.Sub(&escrow.Tokens)
	newSrcAcc, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.True(srcAcc.Escrow.Balance.IsZero(), "src: escrow balance == 0 - after")
	require.Equal(escrow.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	_ = dstAcc.Escrow.Balance.Add(&escrow.Tokens)
	newDstAcc, err := backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "dst: AccountInfo - after")
	require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after")
	require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after")
	require.Equal(dstAcc.Escrow.Balance, newDstAcc.Escrow.Balance, "dst: escrow balance - after")
	require.Equal(dstAcc.Escrow.Balance, newDstAcc.Escrow.TotalShares, "dst: escrow total shares - after")
	require.True(newDstAcc.Escrow.DebondingShares.IsZero(), "dst: escrow debonding shares == 0 - after")

	// Reclaim escrow (subject to debonding).
	debs, err := backend.DebondingDelegations(context.Background(), SrcID)
	require.NoError(err, "DebondingDelegations - before")
	require.Len(debs, 0, "no debonding delegations before reclaiming escrow")

	reclaim := &api.ReclaimEscrow{
		Nonce:   newSrcAcc.General.Nonce,
		Account: DestID,
		Shares:  newDstAcc.Escrow.TotalShares,
	}
	signedReclaim, err := api.SignReclaimEscrow(srcSigner, reclaim)
	require.NoError(err, "Sign ReclaimEscrow")

	err = backend.ReclaimEscrow(context.Background(), signedReclaim)
	require.NoError(err, "ReclaimEscrow")

	// Query debonding delegations.
	debs, err = backend.DebondingDelegations(context.Background(), SrcID)
	require.NoError(err, "DebondingDelegations - after (in debonding)")
	require.Len(debs, 1, "one debonding delegation after reclaiming escrow")
	require.Len(debs[DestID.ToMapKey()], 1, "one debonding delegation after reclaiming escrow")
	require.Equal(reclaim.Shares, debs[DestID.ToMapKey()][0].Shares, "DebondingDelegation: shares")

	// Advance epoch to trigger debonding.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for debonding period to pass.
	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.ReclaimEscrowEvent)
		require.Equal(SrcID, ev.Owner, "Event: owner")
		require.Equal(DestID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive reclaim escrow event")
	}

	_ = srcAcc.General.Balance.Add(&escrow.Tokens)
	newSrcAcc, err = backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - after debond")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after debond")
	require.True(srcAcc.Escrow.Balance.IsZero(), "src: escrow balance == 0 - after debond")
	require.Equal(reclaim.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after debond")

	_ = dstAcc.Escrow.Balance.Sub(&escrow.Tokens)
	newDstAcc, err = backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "dst: AccountInfo - after debond")
	require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after debond")
	require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after debond")
	require.True(newDstAcc.Escrow.Balance.IsZero(), "dst: escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.TotalShares.IsZero(), "dst: escrow total shares == 0 - after debond")
	require.True(newDstAcc.Escrow.DebondingShares.IsZero(), "dst: escrow debonding shares == 0 - after debond")

	debs, err = backend.DebondingDelegations(context.Background(), SrcID)
	require.NoError(err, "DebondingDelegations - after (debonding completed)")
	require.Len(debs, 0, "no debonding delegations after debonding has completed")

	// Reclaim escrow (without enough shares).
	reclaim = &api.ReclaimEscrow{
		Nonce:   newSrcAcc.General.Nonce,
		Account: DestID,
		Shares:  reclaim.Shares,
	}
	signedReclaim, err = api.SignReclaimEscrow(srcSigner, reclaim)
	require.NoError(err, "Sign ReclaimEscrow")

	err = backend.ReclaimEscrow(context.Background(), signedReclaim)
	require.Error(err, "ReclaimEscrow")

	debs, err = backend.DebondingDelegations(context.Background(), SrcID)
	require.NoError(err, "DebondingDelegations")
	require.Len(debs, 0, "no debonding delegations after failed reclaim")
}

func mustGenerateSigner() signature.Signer {
	k, err := memorySigner.NewSigner(rand.Reader)
	if err != nil {
		panic(err)
	}

	return k
}

func QtyFromInt(n int) api.Quantity {
	q := api.NewQuantity()
	if err := q.FromBigInt(big.NewInt(int64(n))); err != nil {
		panic(err)
	}
	return *q
}

func publicKeyFromHex(s string) signature.PublicKey {
	var pk signature.PublicKey
	if err := pk.UnmarshalHex(s); err != nil {
		panic(err)
	}
	return pk
}

func init() {
	b, _ := json.Marshal(debugGenesisState)
	DebugGenesisState = string(b)
}
