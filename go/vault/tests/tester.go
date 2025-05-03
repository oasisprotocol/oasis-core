// Package tests is a collection of vault implementation test cases.
package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	stakingTests "github.com/oasisprotocol/oasis-core/go/staking/tests"
	"github.com/oasisprotocol/oasis-core/go/vault/api"
)

var (
	testSignerA = stakingTests.Accounts.GetSigner(1)
	testAddrA   = stakingTests.Accounts.GetAddress(1)
	testSignerB = stakingTests.Accounts.GetSigner(2)
	testAddrB   = stakingTests.Accounts.GetAddress(2)
	testSignerC = stakingTests.Accounts.GetSigner(3)
	testAddrC   = stakingTests.Accounts.GetAddress(3)
)

type vaultTestState struct {
	vaultAddress staking.Address
}

// VaultImplementationTests exercises the basic functionality of a vault backend.
func VaultImplementationTests(
	t *testing.T,
	vault api.Backend,
	consensus consensusAPI.Service,
) {
	require := require.New(t)
	ctx := context.Background()
	testState := &vaultTestState{}

	// Query state.
	_, err := vault.StateToGenesis(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "StateToGenesis")

	// Run multiple sub-tests.
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, consensusAPI.Service, *vaultTestState)
	}{
		{"TestVaultCreate", testVaultCreate},
		{"TestVaultAuthorizeAction", testVaultAuthorizeAction},
		{"TestVaultWithdraw", testVaultWithdraw},
		{"TestVaultExecuteMessage", testVaultExecuteMessage},
	} {
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, consensus, testState) })
	}
}

func testVaultCreate(t *testing.T, consensus consensusAPI.Service, testState *vaultTestState) {
	require := require.New(t)
	ctx := context.Background()

	create := &api.Create{
		AdminAuthority: api.Authority{
			Addresses: []staking.Address{
				testAddrA,
				testAddrB,
			},
			Threshold: 2,
		},
		SuspendAuthority: api.Authority{
			Addresses: []staking.Address{
				testAddrB,
				testAddrC,
			},
			Threshold: 1,
		},
	}
	tx := api.NewCreateTx(0, nil, create)
	err := consensusAPI.SignAndSubmitTx(ctx, consensus, testSignerA, tx)
	require.NoError(err, "CreateTx")

	acctA, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{
		Owner:  testAddrA,
		Height: consensusAPI.HeightLatest,
	})
	require.NoError(err, "Account")

	// Derive vault address.
	testState.vaultAddress = api.NewVaultAddress(testAddrA, acctA.General.Nonce)

	// Transfer some funds to the vault so they can be withdrawn later.
	xfer := &staking.Transfer{
		To:     testState.vaultAddress,
		Amount: *quantity.NewFromUint64(200),
	}
	tx = staking.NewTransferTx(0, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testSignerA, tx)
	require.NoError(err, "TransferTx to vault")
}

func testVaultAuthorizeAction(t *testing.T, consensus consensusAPI.Service, testState *vaultTestState) {
	require := require.New(t)
	ctx := context.Background()

	act := &api.AuthorizeAction{
		Vault: testState.vaultAddress,
		Nonce: 0,
		Action: api.Action{UpdateWithdrawPolicy: &api.ActionUpdateWithdrawPolicy{
			Address: testAddrC,
			Policy: api.WithdrawPolicy{
				LimitAmount:   *quantity.NewFromUint64(100),
				LimitInterval: 100,
			},
		}},
	}

	// Signer A (1/2).
	tx := api.NewAuthorizeActionTx(0, nil, act)
	err := consensusAPI.SignAndSubmitTx(ctx, consensus, testSignerA, tx)
	require.NoError(err, "AuthorizeActionTx")

	// Signer B (2/2).
	tx = api.NewAuthorizeActionTx(0, nil, act)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testSignerB, tx)
	require.NoError(err, "AuthorizeActionTx")
}

func testVaultWithdraw(t *testing.T, consensus consensusAPI.Service, testState *vaultTestState) {
	require := require.New(t)
	ctx := context.Background()

	// Attempt to withdraw from the vault (previously authorized via policy update).
	withdraw := &staking.Withdraw{
		From:   testState.vaultAddress,
		Amount: *quantity.NewFromUint64(10),
	}
	tx := staking.NewWithdrawTx(0, nil, withdraw)
	err := consensusAPI.SignAndSubmitTx(ctx, consensus, testSignerC, tx)
	require.NoError(err, "Withdraw")

	// Withdrawing over the limit should not be possible (unless we wait for 100 blocks).
	withdraw = &staking.Withdraw{
		From:   testState.vaultAddress,
		Amount: *quantity.NewFromUint64(100),
	}
	tx = staking.NewWithdrawTx(0, nil, withdraw)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testSignerC, tx)
	require.ErrorIs(err, staking.ErrForbidden, "Withdraw")
}

func testVaultExecuteMessage(t *testing.T, consensus consensusAPI.Service, testState *vaultTestState) {
	require := require.New(t)
	ctx := context.Background()

	acctBt1, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{
		Owner:  testAddrB,
		Height: consensusAPI.HeightLatest,
	})
	require.NoError(err, "Account")

	act := &api.AuthorizeAction{
		Vault: testState.vaultAddress,
		Nonce: 1,
		Action: api.Action{ExecuteMessage: &api.ActionExecuteMessage{
			Method: staking.MethodTransfer,
			Body: cbor.Marshal(staking.Transfer{
				To:     testAddrB,
				Amount: *quantity.NewFromUint64(42),
			}),
		}},
	}

	// Signer A (1/2).
	tx := api.NewAuthorizeActionTx(0, nil, act)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testSignerA, tx)
	require.NoError(err, "AuthorizeActionTx")

	// Signer B (2/2).
	tx = api.NewAuthorizeActionTx(0, nil, act)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testSignerB, tx)
	require.NoError(err, "AuthorizeActionTx")

	// Check that transfer has been executed.
	acctBt2, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{
		Owner:  testAddrB,
		Height: consensusAPI.HeightLatest,
	})
	require.NoError(err, "Account")

	balanceDiff := acctBt2.General.Balance
	err = balanceDiff.Sub(&acctBt1.General.Balance)
	require.NoError(err, "transfer should be successful")
	require.EqualValues(42, balanceDiff.ToBigInt().Uint64(), "transfer should be successful")
}
