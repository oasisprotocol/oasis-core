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

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/staking/api"
)

const recvTimeout = 5 * time.Second

var (
	// DebugGenesisState is the string representation of the initial
	// genesis state that the backend MUST be populated with.
	DebugGenesisState string

	debugGenesisState = api.Genesis{
		TotalSupply: testTotalSupply,
		Ledger: map[signature.MapKey]*api.GenesisLedgerEntry{
			SrcID.ToMapKey(): &api.GenesisLedgerEntry{
				GeneralBalance: testTotalSupply,
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
func StakingImplementationTests(t *testing.T, backend api.Backend) {
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, api.Backend)
	}{
		{"InitialEnv", testInitialEnv},
		{"Transfer", testTransfer},
		{"TransferSelf", testSelfTransfer},
		{"Burn", testBurn},
		{"Escrow", testEscrow},
	} {
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, backend) })
	}
}

func testInitialEnv(t *testing.T, backend api.Backend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background())
	require.NoError(err, "TotalSupply")
	require.Equal(&testTotalSupply, totalSupply, "TotalSupply - value")

	accounts, err := backend.Accounts(context.Background())
	require.NoError(err, "Accounts")
	require.Len(accounts, 1, "Accounts - nr entries")
	require.Equal(SrcID, accounts[0], "Accounts[0] == testID")

	generalBalance, escrowBalance, debond, nonce, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo")
	require.Equal(&testTotalSupply, generalBalance, "src: generalBalance")
	require.True(escrowBalance.IsZero(), "src: escrowBalance")
	require.EqualValues(0, debond, "src: debond start time")
	require.EqualValues(0, nonce, "src: nonce")

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

func testTransfer(t *testing.T, backend api.Backend) {
	require := require.New(t)

	destBalance, _, _, nonce, err := backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "dest: AccountInfo")
	require.True(destBalance.IsZero(), "dest: generalBalance - before")
	require.EqualValues(0, nonce, "dest: nonce - before")

	srcBalance, _, _, nonce, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - before")

	ch, sub := backend.WatchTransfers()
	defer sub.Close()

	xfer := &api.Transfer{
		Nonce:  nonce,
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

	_ = srcBalance.Sub(&xfer.Tokens)
	newSrcBalance, _, _, nonce, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcBalance, newSrcBalance, "src: generalBalance")
	require.Equal(xfer.Nonce+1, nonce, "src: nonce")

	destBalance, _, _, nonce, err = backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "dest: AccountInfo - after")
	require.Equal(&xfer.Tokens, destBalance, "dest: generalBalance - after")
	require.EqualValues(0, nonce, "dest: nonce - after")

	// Transfers that exceed available balance should fail.
	xfer.Nonce = nonce
	_ = newSrcBalance.Add(&qtyOne)
	xfer.Tokens = *newSrcBalance

	signed, err = api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer - fail test")

	err = backend.Transfer(context.Background(), signed)
	require.Error(err, "Transfer - more than available balance")
}

func testSelfTransfer(t *testing.T, backend api.Backend) {
	require := require.New(t)

	srcBalance, _, _, nonce, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - before")

	ch, sub := backend.WatchTransfers()
	defer sub.Close()

	xfer := &api.Transfer{
		Nonce:  nonce,
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

	newSrcBalance, _, _, nonce, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcBalance, newSrcBalance, "src: generalBalance")
	require.Equal(xfer.Nonce+1, nonce, "src: nonce")

	// Self transfers that are more than the balance should fail.
	xfer.Nonce = nonce
	_ = newSrcBalance.Add(&qtyOne)
	xfer.Tokens = *newSrcBalance

	signed, err = api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer - fail test")

	err = backend.Transfer(context.Background(), signed)
	require.Error(err, "Transfer - more than available balance")
}

func testBurn(t *testing.T, backend api.Backend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background())
	require.NoError(err, "TotalSupply - before")

	srcBalance, _, _, nonce, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo")

	ch, sub := backend.WatchBurns()
	defer sub.Close()

	burn := &api.Burn{
		Nonce:  nonce,
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

	_ = srcBalance.Sub(&burn.Tokens)
	newSrcBalance, _, _, nonce, err := backend.AccountInfo(context.Background(), SrcID)
	require.NoError(err, "src: AccountInfo")
	require.Equal(srcBalance, newSrcBalance, "src: generalBalance - after")
	require.EqualValues(burn.Nonce+1, nonce, "src: nonce - after")
}

func testEscrow(t *testing.T, backend api.Backend) {
	require := require.New(t)

	generalBalance, escrowBalance, _, nonce, err := backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "AccountInfo - before")
	require.False(generalBalance.IsZero(), "dest: generalBalance != 0")
	require.True(escrowBalance.IsZero(), "dest: escrowBalance == 0")

	ch, sub := backend.WatchEscrows()
	defer sub.Close()

	escrow := &api.Escrow{
		Nonce:  nonce,
		Tokens: *generalBalance,
	}
	signed, err := api.SignEscrow(destSigner, escrow)
	require.NoError(err, "Sign escrow")

	err = backend.AddEscrow(context.Background(), signed)
	require.NoError(err, "AddEscrow")

	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.EscrowEvent)
		require.Equal(DestID, ev.Owner, "Event: owner")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	tmpBalance := generalBalance

	generalBalance, escrowBalance, _, _, err = backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "AccountInfo - escrowed")
	require.True(generalBalance.IsZero(), "dest: generalBalance == 0")
	require.Equal(tmpBalance, escrowBalance, "dest: escrowBalance == oldGeneralBalance")

	reclaim := &api.ReclaimEscrow{
		Nonce:  nonce + 1,
		Tokens: *escrowBalance,
	}
	signedReclaim, err := api.SignReclaimEscrow(destSigner, reclaim)
	require.NoError(err, "Sign ReclaimEscrow")

	err = backend.ReclaimEscrow(context.Background(), signedReclaim)
	require.NoError(err, "ReclaimEscrow")

	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.ReclaimEscrowEvent)
		require.Equal(DestID, ev.Owner, "Event: owner")
		require.Equal(reclaim.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	generalBalance, escrowBalance, _, _, err = backend.AccountInfo(context.Background(), DestID)
	require.NoError(err, "AccountInfo - escrowed")
	require.Equal(tmpBalance, generalBalance, "dest: generalBalance == oldGeneralBalance")
	require.True(escrowBalance.IsZero(), "dest: escrowBalance == 0")

	escrowBackend, ok := backend.(api.EscrowBackend)
	if !ok {
		// Can't test Take/Release escrow in a generic manner.
		t.Logf("non-EscrowBackend, skipping Take/ReleaseEscrow tests")
		return
	}

	// Nothing implements EscrowBackend, punt on running tests for now.
	_ = escrowBackend
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
