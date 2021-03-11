package staking

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestIsTransferPermitted(t *testing.T) {
	for _, tt := range []struct {
		msg       string
		params    *staking.ConsensusParameters
		fromAddr  staking.Address
		permitted bool
	}{
		{
			"no disablement",
			&staking.ConsensusParameters{},
			staking.Address{},
			true,
		},
		{
			"all disabled",
			&staking.ConsensusParameters{
				DisableTransfers: true,
			},
			staking.Address{},
			false,
		},
		{
			"not whitelisted",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[staking.Address]bool{
					{1}: true,
				},
			},
			staking.Address{},
			false,
		},
		{
			"whitelisted",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[staking.Address]bool{
					{}: true,
				},
			},
			staking.Address{},
			true,
		},
	} {
		require.Equal(t, tt.permitted, isTransferPermitted(tt.params, tt.fromAddr), tt.msg)
	}
}

func TestReservedAddresses(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	stakeState := stakingState.NewMutableState(ctx.State())

	err = stakeState.SetConsensusParameters(ctx, &staking.ConsensusParameters{
		MaxAllowances: 1,
	})
	require.NoError(err, "setting staking consensus parameters should not error")

	app := &stakingApplication{
		state: appState,
	}

	txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer txCtx.Close()

	// Create a new test public key, set it as the tx signer and create a new reserved address from it.
	testPK := signature.NewPublicKey("badfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	txCtx.SetTxSigner(testPK)
	_ = staking.NewReservedAddress(testPK)

	// Make sure all transaction types fail for the reserved address.
	err = app.transfer(txCtx, stakeState, nil)
	require.EqualError(err, "staking: forbidden by policy", "transfer for reserved address should error")

	err = app.burn(txCtx, stakeState, nil)
	require.EqualError(err, "staking: forbidden by policy", "burn for reserved address should error")

	var q quantity.Quantity
	_ = q.FromInt64(1_000)

	// NOTE: We need to specify escrow amount since that is checked before the check for reserved address.
	err = app.addEscrow(txCtx, stakeState, &staking.Escrow{Amount: *q.Clone()})
	require.EqualError(err, "staking: forbidden by policy", "adding escrow for reserved address should error")

	// NOTE: We need to specify reclaim escrow shares since that is checked before the check for reserved address.
	err = app.reclaimEscrow(txCtx, stakeState, &staking.ReclaimEscrow{Shares: *q.Clone()})
	require.EqualError(err, "staking: forbidden by policy", "reclaim escrow for reserved address should error")

	err = app.amendCommissionSchedule(txCtx, stakeState, nil)
	require.EqualError(err, "staking: forbidden by policy", "amending commission schedule for reserved address should error")

	err = app.allow(txCtx, stakeState, &staking.Allow{})
	require.EqualError(err, "staking: forbidden by policy", "allow for reserved address should error")

	err = app.withdraw(txCtx, stakeState, &staking.Withdraw{})
	require.EqualError(err, "staking: forbidden by policy", "withdraw for reserved address should error")
}

func TestAllow(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	stakeState := stakingState.NewMutableState(ctx.State())

	app := &stakingApplication{
		state: appState,
	}

	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	pk2 := signature.NewPublicKey("bbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr2 := staking.NewAddress(pk2)
	pk3 := signature.NewPublicKey("cccfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr3 := staking.NewAddress(pk3)

	reservedPK := signature.NewPublicKey("badaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	reservedAddr := staking.NewReservedAddress(reservedPK)

	for _, tc := range []struct {
		msg               string
		params            *staking.ConsensusParameters
		txSigner          signature.PublicKey
		allow             *staking.Allow
		err               error
		expectedAllowance uint64
	}{
		{
			"should fail with disabled transfers",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				MaxAllowances:    42,
			},
			pk1,
			&staking.Allow{
				Beneficiary:  addr2,
				AmountChange: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
			0,
		},
		{
			"should fail with zero max allowances",
			&staking.ConsensusParameters{
				MaxAllowances: 0,
			},
			pk1,
			&staking.Allow{
				Beneficiary:  addr2,
				AmountChange: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
			0,
		},
		{
			"should fail with equal addresses",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk1,
			&staking.Allow{
				Beneficiary:  addr1,
				AmountChange: *quantity.NewFromUint64(10),
			},
			staking.ErrInvalidArgument,
			0,
		},
		{
			"should fail with reserved signer address",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			reservedPK,
			&staking.Allow{
				Beneficiary:  addr2,
				AmountChange: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
			0,
		},
		{
			"should fail with reserved beneficiary address",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk1,
			&staking.Allow{
				Beneficiary:  reservedAddr,
				AmountChange: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
			0,
		},
		{
			"should succeed",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk1,
			&staking.Allow{
				Beneficiary:  addr2,
				AmountChange: *quantity.NewFromUint64(10),
			},
			nil,
			10,
		},
		{
			"should succeed (adding to existing allowance)",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk1,
			&staking.Allow{
				Beneficiary:  addr2,
				AmountChange: *quantity.NewFromUint64(10),
			},
			nil,
			20,
		},
		{
			"should succeed (subtracting from existing allowance)",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk1,
			&staking.Allow{
				Beneficiary:  addr2,
				Negative:     true,
				AmountChange: *quantity.NewFromUint64(5),
			},
			nil,
			15,
		},
		{
			"should fail if too many allowances",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk1,
			&staking.Allow{
				Beneficiary:  addr3,
				AmountChange: *quantity.NewFromUint64(10),
			},
			staking.ErrTooManyAllowances,
			0,
		},
	} {
		err = stakeState.SetConsensusParameters(ctx, tc.params)
		require.NoError(err, "setting staking consensus parameters should not error")

		txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
		defer txCtx.Close()
		txCtx.SetTxSigner(tc.txSigner)

		err = app.allow(txCtx, stakeState, tc.allow)
		require.Equal(tc.err, err, tc.msg)

		addr := staking.NewAddress(tc.txSigner)
		if addr.IsReserved() {
			continue
		}
		acct, err := stakeState.Account(txCtx, addr)
		require.NoError(err, "reading account state should not error")

		require.Equal(
			*quantity.NewFromUint64(tc.expectedAllowance),
			acct.General.Allowances[tc.allow.Beneficiary],
			"allowance should be correctly set after operation completes",
		)
	}
}

func TestWithdraw(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	stakeState := stakingState.NewMutableState(ctx.State())

	app := &stakingApplication{
		state: appState,
	}

	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	pk2 := signature.NewPublicKey("bbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr2 := staking.NewAddress(pk2)
	pk3 := signature.NewPublicKey("cccfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr3 := staking.NewAddress(pk3)

	reservedPK := signature.NewPublicKey("badaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	reservedAddr := staking.NewReservedAddress(reservedPK)

	// Configure an allowance.
	err = stakeState.SetAccount(ctx, addr1, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(50),
			Allowances: map[staking.Address]quantity.Quantity{
				// addr2 is allowed to withdraw up to 100 base units from addr1's account.
				addr2: *quantity.NewFromUint64(100),
				// addr3 is allowed to withdraw up to 25 base units from addr1's account.
				addr3: *quantity.NewFromUint64(25),
			},
		},
	})
	require.NoError(err, "SetAccount")

	for _, tc := range []struct {
		msg      string
		params   *staking.ConsensusParameters
		txSigner signature.PublicKey
		withdraw *staking.Withdraw
		err      error
	}{
		{
			"should fail with disabled transfers",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				MaxAllowances:    42,
			},
			pk2,
			&staking.Withdraw{
				From:   addr1,
				Amount: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
		},
		{
			"should fail with zero max allowances",
			&staking.ConsensusParameters{
				MaxAllowances: 0,
			},
			pk2,
			&staking.Withdraw{
				From:   addr1,
				Amount: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
		},
		{
			"should fail with equal addresses",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk2,
			&staking.Withdraw{
				From:   addr2,
				Amount: *quantity.NewFromUint64(10),
			},
			staking.ErrInvalidArgument,
		},
		{
			"should fail with reserved signer address",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			reservedPK,
			&staking.Withdraw{
				From:   addr1,
				Amount: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
		},
		{
			"should fail with reserved from address",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk2,
			&staking.Withdraw{
				From:   reservedAddr,
				Amount: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
		},
		{
			"should fail if there is no allowance",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk2,
			&staking.Withdraw{
				From:   addr3,
				Amount: *quantity.NewFromUint64(10),
			},
			staking.ErrForbidden,
		},
		{
			"should fail if there is not enough allowance",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk2,
			&staking.Withdraw{
				From:   addr1,
				Amount: *quantity.NewFromUint64(10_000),
			},
			staking.ErrForbidden,
		},
		{
			"should fail if there is not enough balance",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk2,
			&staking.Withdraw{
				From:   addr1,
				Amount: *quantity.NewFromUint64(90),
			},
			staking.ErrInsufficientBalance,
		},
		{
			"should succeed",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk2,
			&staking.Withdraw{
				From:   addr1,
				Amount: *quantity.NewFromUint64(25),
			},
			nil,
		},
		{
			"should succeed",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk3,
			&staking.Withdraw{
				From:   addr1,
				Amount: *quantity.NewFromUint64(25),
			},
			nil,
		},
		{
			"should fail if there is not enough balance",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk2,
			&staking.Withdraw{
				From:   addr1,
				Amount: *quantity.NewFromUint64(1),
			},
			staking.ErrInsufficientBalance,
		},
		{
			"should fail if there is not enough allowance",
			&staking.ConsensusParameters{
				MaxAllowances: 1,
			},
			pk2,
			&staking.Withdraw{
				From:   addr3,
				Amount: *quantity.NewFromUint64(1),
			},
			staking.ErrForbidden,
		},
	} {
		err = stakeState.SetConsensusParameters(ctx, tc.params)
		require.NoError(err, "setting staking consensus parameters should not error")

		txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
		defer txCtx.Close()
		txCtx.SetTxSigner(tc.txSigner)

		beforeAcct, err := stakeState.Account(txCtx, tc.withdraw.From)
		if !tc.withdraw.From.IsReserved() {
			require.NoError(err, "reading account state should not error")
		}

		err = app.withdraw(txCtx, stakeState, tc.withdraw)
		require.Equal(tc.err, err, tc.msg)

		if tc.withdraw.From.IsReserved() {
			continue
		}
		afterAcct, err := stakeState.Account(txCtx, tc.withdraw.From)
		require.NoError(err, "reading account state should not error")

		expectedBalance := beforeAcct.General.Balance
		switch tc.err {
		case nil:
			err = expectedBalance.Sub(&tc.withdraw.Amount)
			require.NoError(err, "computing expected balance should not fail")

			if expectedBalance.IsZero() {
				expectedBalance = *quantity.NewQuantity()
			}
		default:
			// Balance should be unchanged.
		}
		require.Equal(expectedBalance, afterAcct.General.Balance, "general balance should be correct after withdraw")
	}
}

func TestAddEscrow(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	stakeState := stakingState.NewMutableState(ctx.State())

	app := &stakingApplication{
		state: appState,
	}

	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	pk2 := signature.NewPublicKey("bbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr2 := staking.NewAddress(pk2)
	pk3 := signature.NewPublicKey("cccfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr3 := staking.NewAddress(pk3)

	reservedPK := signature.NewPublicKey("badaaaffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_ = staking.NewReservedAddress(reservedPK)

	err = stakeState.SetAccount(ctx, addr1, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(100_000),
		},
	})
	require.NoError(err, "SetAccount1")

	err = stakeState.SetAccount(ctx, addr2, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(100_000),
		},
	})
	require.NoError(err, "SetAccount2")

	for _, tc := range []struct {
		msg      string
		params   *staking.ConsensusParameters
		txSigner signature.PublicKey
		escrow   *staking.Escrow
		err      error
	}{
		{
			"should fail when under min delegation amount",
			&staking.ConsensusParameters{
				MinDelegationAmount: *quantity.NewFromUint64(1000),
			},
			pk1,
			&staking.Escrow{
				Account: addr2,
				Amount:  *quantity.NewFromUint64(100),
			},
			staking.ErrUnderMinDelegationAmount,
		},
		{
			"should succeed when over min delegation amount",
			&staking.ConsensusParameters{
				MinDelegationAmount: *quantity.NewFromUint64(1000),
			},
			pk2,
			&staking.Escrow{
				Account: addr1,
				Amount:  *quantity.NewFromUint64(10000),
			},
			nil,
		},
		{
			"should fail when not enough balance",
			&staking.ConsensusParameters{},
			pk3,
			&staking.Escrow{
				Account: addr1,
				Amount:  *quantity.NewFromUint64(1000),
			},
			quantity.ErrInsufficientBalance,
		},
		{
			"should fail when using reserved address",
			&staking.ConsensusParameters{},
			reservedPK,
			&staking.Escrow{
				Account: addr3,
				Amount:  *quantity.NewFromUint64(1000),
			},
			staking.ErrForbidden,
		},
	} {
		err = stakeState.SetConsensusParameters(ctx, tc.params)
		require.NoError(err, "setting staking consensus parameters should not error")

		txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
		defer txCtx.Close()
		txCtx.SetTxSigner(tc.txSigner)

		err = app.addEscrow(txCtx, stakeState, tc.escrow)
		require.Equal(tc.err, err, tc.msg)
	}
}

func TestAllowEscrowMessages(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	stakeState := stakingState.NewMutableState(ctx.State())
	app := &stakingApplication{
		state: appState,
	}
	err = stakeState.SetConsensusParameters(ctx, &staking.ConsensusParameters{
		MaxAllowances: 1,
	})
	require.NoError(err, "setting staking consensus parameters should not error")

	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)

	err = stakeState.SetAccount(ctx, addr1, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(50),
		},
	})
	require.NoError(err, "SetAccount")

	txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer txCtx.Close()

	// Add escrow transaction should be allowed.
	txCtx.SetTxSigner(pk1)
	err = app.addEscrow(txCtx, stakeState, &staking.Escrow{Account: addr1, Amount: *quantity.NewFromUint64(10)})
	require.NoError(err, "add escrow transaction should work")

	// Reclaim escrow transaction should be allowed.
	err = app.reclaimEscrow(txCtx, stakeState, &staking.ReclaimEscrow{Account: addr1, Shares: *quantity.NewFromUint64(1)})
	require.NoError(err, "reclaim escrow transaction should work")

	txCtx = txCtx.WithMessageExecution()
	// Add escrow message should not be allowed.
	err = app.addEscrow(txCtx, stakeState, &staking.Escrow{Account: addr1, Amount: *quantity.NewFromUint64(10)})
	require.Equal(staking.ErrForbidden, err, "add escrow message should be denied")

	// Reclaim escrow message should not be allowed.
	err = app.reclaimEscrow(txCtx, stakeState, &staking.ReclaimEscrow{Account: addr1, Shares: *quantity.NewFromUint64(1)})
	require.Error(staking.ErrForbidden, err, "reclaim escrow transaction should work")

	err = stakeState.SetConsensusParameters(ctx, &staking.ConsensusParameters{
		AllowEscrowMessages: true,
	})
	require.NoError(err, "setting staking consensus parameters should not error")

	// Escrow message should be allowed.
	err = app.addEscrow(txCtx, stakeState, &staking.Escrow{Account: addr1, Amount: *quantity.NewFromUint64(10)})
	require.NoError(err, "add escrow message should be allowed")

	err = app.reclaimEscrow(txCtx, stakeState, &staking.ReclaimEscrow{Account: addr1, Shares: *quantity.NewFromUint64(1)})
	require.NoError(err, "reclaim escrow message should work")
}
