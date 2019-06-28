// Pacakge tests is a collection of staking token backend implementation tests.
package tests

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/staking/api"
)

const recvTimeout = 1 * time.Second

var (
	// InitialBalancesArg is a viper.Set compatible representation of
	// of the genesis state that the backend MUST be populated with
	// for the tests to pass.
	InitialBalancesArg = buildInitialBalancesArg()

	initialBalances = map[signature.MapKey]*big.Int{
		srcID.ToMapKey(): testTotalSupply.ToBigInt(),
	}

	testTotalSupply = qtyFromInt(math.MaxInt64)

	srcPrivateKey  = mustGeneratePrivateKey()
	srcID          = srcPrivateKey.Public()
	destPrivateKey = mustGeneratePrivateKey()
	destID         = destPrivateKey.Public()
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
		{"Allowance", testAllowance},
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
	require.Equal(srcID, accounts[0], "Accounts[0] == testID")

	generalBalance, escrowBalance, nonce, err := backend.AccountInfo(context.Background(), srcID)
	require.NoError(err, "src: AccountInfo")
	require.Equal(&testTotalSupply, generalBalance, "src: generalBalance")
	require.True(escrowBalance.IsZero(), "src: escrowBalance")
	require.EqualValues(0, nonce, "src: nonce")

	commonPool, err := backend.CommonPool(context.Background())
	require.NoError(err, "CommonPool")
	require.True(commonPool.IsZero(), "CommonPool - initial value")
}

func testTransfer(t *testing.T, backend api.Backend) {
	require := require.New(t)

	destBalance, _, nonce, err := backend.AccountInfo(context.Background(), destID)
	require.NoError(err, "dest: AccountInfo")
	require.True(destBalance.IsZero(), "dest: generalBalance - before")
	require.EqualValues(0, nonce, "dest: nonce - before")

	srcBalance, _, nonce, err := backend.AccountInfo(context.Background(), srcID)
	require.NoError(err, "src: AccountInfo - before")

	ch, sub := backend.WatchTransfers()
	defer sub.Close()

	xfer := &api.Transfer{
		Nonce:  nonce,
		To:     destID,
		Tokens: qtyFromInt(math.MaxUint8),
	}
	signed, err := api.SignTransfer(srcPrivateKey, xfer)
	require.NoError(err, "Sign xfer")

	err = backend.Transfer(context.Background(), signed)
	require.NoError(err, "Transfer")

	select {
	case ev := <-ch:
		require.Equal(srcID, ev.From, "Event: from")
		require.Equal(destID, ev.To, "Event: to")
		require.Equal(xfer.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive transfer event")
	}

	_ = srcBalance.Sub(&xfer.Tokens)
	newSrcBalance, _, nonce, err := backend.AccountInfo(context.Background(), srcID)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcBalance, newSrcBalance, "src: generalBalance")
	require.Equal(xfer.Nonce+1, nonce, "src: nonce")

	destBalance, _, nonce, err = backend.AccountInfo(context.Background(), destID)
	require.NoError(err, "dest: AccountInfo - after")
	require.Equal(&xfer.Tokens, destBalance, "dest: generalBalance - after")
	require.EqualValues(0, nonce, "dest: nonce - after")
}

func testAllowance(t *testing.T, backend api.Backend) {
	require := require.New(t)

	srcBalance, _, nonce, err := backend.AccountInfo(context.Background(), srcID)
	require.NoError(err, "src: AccountInfo - before")

	appCh, appSub := backend.WatchApprovals()
	defer appSub.Close()

	approval := &api.Approval{
		Nonce:   nonce,
		Spender: destID,
		Tokens:  qtyFromInt(math.MaxUint16),
	}
	signed, err := api.SignApproval(srcPrivateKey, approval)
	require.NoError(err, "Sign approval")

	err = backend.Approve(context.Background(), signed)
	require.NoError(err, "Approve")

	select {
	case ev := <-appCh:
		require.Equal(srcID, ev.Owner, "Event: owner")
		require.Equal(destID, ev.Spender, "Event: spender")
		require.Equal(approval.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive approval event")
	}

	allowance, err := backend.Allowance(context.Background(), srcID, destID)
	require.NoError(err, "Allowance")
	require.EqualValues(&approval.Tokens, allowance, "allowance is set")

	xferCh, xferSub := backend.WatchTransfers()
	defer xferSub.Close()

	destBalance, _, _, err := backend.AccountInfo(context.Background(), destID)
	require.NoError(err, "dest: AccountInfo - before")

	withdrawal := &api.Withdrawal{
		Nonce:  approval.Nonce + 1, // nb: Uses `from` nonce! Change?
		From:   srcID,
		Tokens: approval.Tokens,
	}
	signedW, err := api.SignWithdrawal(destPrivateKey, withdrawal)
	require.NoError(err, "Sign withdrawal")

	err = backend.Withdraw(context.Background(), signedW)
	require.NoError(err, "Withdraw")

	select {
	case ev := <-xferCh:
		require.Equal(srcID, ev.From, "Event: from")
		require.Equal(destID, ev.To, "Event: to")
		require.Equal(withdrawal.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive transfer event (withdrawal)")
	}

	allowance, err = backend.Allowance(context.Background(), srcID, destID)
	require.NoError(err, "Allowance - after")
	require.True(allowance.IsZero(), "allowance is zero")

	_ = srcBalance.Sub(&withdrawal.Tokens)
	balance, _, nonce, err := backend.AccountInfo(context.Background(), srcID)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcBalance, balance, "src: balance - after")
	require.Equal(withdrawal.Nonce+1, nonce, "src: nonce - after")

	_ = destBalance.Add(&withdrawal.Tokens)
	balance, _, _, err = backend.AccountInfo(context.Background(), destID)
	require.NoError(err, "dest: AccountInfo - after")
	require.Equal(destBalance, balance, "dest: balance - after")
}

func testBurn(t *testing.T, backend api.Backend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background())
	require.NoError(err, "TotalSupply - before")

	srcBalance, _, nonce, err := backend.AccountInfo(context.Background(), srcID)
	require.NoError(err, "src: AccountInfo")

	ch, sub := backend.WatchBurns()
	defer sub.Close()

	burn := &api.Burn{
		Nonce:  nonce,
		Tokens: qtyFromInt(math.MaxUint32),
	}
	signed, err := api.SignBurn(srcPrivateKey, burn)
	require.NoError(err, "Sign burn")

	err = backend.Burn(context.Background(), signed)
	require.NoError(err, "Burn")

	select {
	case ev := <-ch:
		require.Equal(srcID, ev.Owner, "Event: owner")
		require.Equal(burn.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive burn event")
	}

	_ = totalSupply.Sub(&burn.Tokens)
	newTotalSupply, err := backend.TotalSupply(context.Background())
	require.NoError(err, "TotalSupply - after")
	require.Equal(totalSupply, newTotalSupply, "totalSupply is reduced by burn")

	_ = srcBalance.Sub(&burn.Tokens)
	newSrcBalance, _, nonce, err := backend.AccountInfo(context.Background(), srcID)
	require.NoError(err, "src: AccountInfo")
	require.Equal(srcBalance, newSrcBalance, "src: generalBalance - after")
	require.EqualValues(burn.Nonce+1, nonce, "src: nonce - after")
}

func testEscrow(t *testing.T, backend api.Backend) {
	require := require.New(t)

	generalBalance, escrowBalance, nonce, err := backend.AccountInfo(context.Background(), destID)
	require.NoError(err, "AccountInfo - before")
	require.False(generalBalance.IsZero(), "dest: generalBalance != 0")
	require.True(escrowBalance.IsZero(), "dest: escrowBalance == 0")

	ch, sub := backend.WatchEscrows()
	defer sub.Close()

	escrow := &api.Escrow{
		Nonce:  nonce,
		Tokens: *generalBalance,
	}
	signed, err := api.SignEscrow(destPrivateKey, escrow)
	require.NoError(err, "Sign escrow")

	err = backend.AddEscrow(context.Background(), signed)
	require.NoError(err, "AddEscrow")

	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.EscrowEvent)
		require.Equal(destID, ev.Owner, "Event: owner")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	tmpBalance := generalBalance

	generalBalance, escrowBalance, _, err = backend.AccountInfo(context.Background(), destID)
	require.NoError(err, "AccountInfo - escrowed")
	require.True(generalBalance.IsZero(), "dest: generalBalance == 0")
	require.Equal(tmpBalance, escrowBalance, "dest: escrowBalance == oldGeneralBalance")

	escrowBackend, ok := backend.(api.EscrowBackend)
	if !ok {
		// Can't test Take/Release escrow in a generic manner.
		t.Logf("non-EscrowBackend, skipping Take/ReleaseEscrow tests")
		return
	}

	toSlash := qtyFromInt(math.MaxUint8)
	err = escrowBackend.TakeEscrow(context.Background(), destID, &toSlash)
	require.NoError(err, "TakeEscrow")

	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.TakeEscrowEvent)
		require.Equal(destID, ev.Owner, "Event: owner")
		require.Equal(toSlash, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive take escrow event")
	}

	tmpBalance = escrowBalance
	_ = tmpBalance.Sub(&toSlash)

	_, escrowBalance, _, err = backend.AccountInfo(context.Background(), destID)
	require.NoError(err, "AccountInfo - take escrowed")
	require.Equal(tmpBalance, escrowBalance, "dest: escrowBalance was decreased")

	err = escrowBackend.ReleaseEscrow(context.Background(), destID)
	require.NoError(err, "ReleaseEscrow")

	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.ReleaseEscrowEvent)
		require.Equal(destID, ev.Owner, "Event: owner")
		require.Equal(tmpBalance, &ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive release escrow event")
	}

	generalBalance, escrowBalance, _, err = backend.AccountInfo(context.Background(), destID)
	require.NoError(err, "AccountInfo - release escrowed")
	require.Equal(tmpBalance, generalBalance, "dest: generalBalance - released")
	require.True(escrowBalance.IsZero(), "dest: escrowBalance == 0 - released")
}

func mustGeneratePrivateKey() signature.PrivateKey {
	k, err := signature.NewPrivateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return k
}

func buildInitialBalancesArg() map[string]string {
	m := make(map[string]string)
	for k, v := range initialBalances {
		m[k.String()] = v.String()
	}

	return m
}

func qtyFromInt(n int) api.Quantity {
	q := api.NewQuantity()
	if err := q.FromBigInt(big.NewInt(int64(n))); err != nil {
		panic(err)
	}
	return *q
}
