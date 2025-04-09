package vault

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

var (
	testAddrA = staking.NewModuleAddress("test", "a")
	testAddrB = staking.NewModuleAddress("test", "b")
	testAddrC = staking.NewModuleAddress("test", "c")
	testAddrD = staking.NewModuleAddress("test", "d")
	testAddrE = staking.NewModuleAddress("test", "e")
)

func TestCreate(t *testing.T) {
	require := require.New(t)

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	app := &vaultApplication{
		state: appState,
	}

	validVaultCreateArgs := &vault.Create{
		AdminAuthority: vault.Authority{
			Addresses: []staking.Address{
				testAddrA,
				testAddrB,
			},
			Threshold: 2,
		},
		SuspendAuthority: vault.Authority{
			Addresses: []staking.Address{
				testAddrB,
				testAddrC,
				testAddrD,
			},
			Threshold: 1,
		},
	}

	state := vaultState.NewMutableState(ctx.State())
	err := state.SetConsensusParameters(ctx, &vault.ConsensusParameters{
		MaxAuthorityAddresses: 3,
	})
	require.NoError(err, "SetConsensusParameters")

	ctx = appState.NewContext(abciAPI.ContextDeliverTx)
	defer ctx.Close()

	for _, tc := range []struct {
		msg               string
		nonce             uint64
		args              *vault.Create
		ok                bool
		shouldExistOnFail bool
	}{
		{
			"create should fail with invalid auhorities",
			0,
			&vault.Create{},
			false,
			false,
		},
		{
			"create should fail with invalid admin authority",
			0,
			&vault.Create{
				// Empty admin authority.
				SuspendAuthority: validVaultCreateArgs.SuspendAuthority,
			},
			false,
			false,
		},
		{
			"create should fail with invalid suspend authority",
			0,
			&vault.Create{
				AdminAuthority: validVaultCreateArgs.AdminAuthority,
				// Empty suspend authority.
			},
			false,
			false,
		},
		{
			"create should fail with authority with too many addresses",
			0,
			&vault.Create{
				AdminAuthority: vault.Authority{
					Addresses: []staking.Address{
						testAddrA,
						testAddrB,
						testAddrC,
						testAddrD,
					},
					Threshold: 1,
				},
				SuspendAuthority: validVaultCreateArgs.SuspendAuthority,
			},
			false,
			false,
		},
		{
			"create should fail with authority with duplicate addresses",
			0,
			&vault.Create{
				AdminAuthority: vault.Authority{
					Addresses: []staking.Address{
						testAddrA,
						testAddrA,
						testAddrB,
					},
					Threshold: 1,
				},
				SuspendAuthority: validVaultCreateArgs.SuspendAuthority,
			},
			false,
			false,
		},
		{
			"create should succeed with valid arguments",
			0,
			validVaultCreateArgs,
			true,
			false,
		},
		{
			"create should fail if vault already exists (not possible due to nonce advance)",
			0,
			validVaultCreateArgs,
			false,
			true,
		},
		{
			"create should succeed for a second vault created by the same caller",
			1,
			validVaultCreateArgs,
			true,
			false,
		},
	} {
		// Prepare caller nonce.
		stakeState := stakingState.NewMutableState(ctx.State())
		err = stakeState.SetAccount(ctx, ctx.CallerAddress(), &staking.Account{
			General: staking.GeneralAccount{
				Nonce: tc.nonce,
			},
		})
		require.NoError(err, "SetAccount")

		expectedVaultAddr := vault.NewVaultAddress(ctx.CallerAddress(), tc.nonce)
		state = vaultState.NewMutableState(ctx.State())

		err = app.create(ctx, tc.args)
		switch tc.ok {
		case false:
			// Creation should fail.
			require.Error(err, tc.msg)

			if !tc.shouldExistOnFail {
				// Ensure that no vault has been created.
				_, err = state.Vault(ctx, expectedVaultAddr)
				require.Error(err, "Vault")
			}
		case true:
			// Creation should succeed.
			require.NoError(err, tc.msg)

			// Ensure that a vault has been created at the correct address.
			vlt, err := state.Vault(ctx, expectedVaultAddr)
			require.NoError(err, "Vault")
			require.EqualValues(tc.args.AdminAuthority, vlt.AdminAuthority)
			require.EqualValues(tc.args.SuspendAuthority, vlt.SuspendAuthority)

			// Ensure that a withdraw handler has been configured for the vault's address.
			stakeState := stakingState.NewMutableState(ctx.State())
			vaultAcct, err := stakeState.Account(ctx, expectedVaultAddr)
			require.NoError(err, "Account")
			require.Len(vaultAcct.General.Hooks, 1)
		}
	}
}

type testMsgDispatcher struct {
	delivered []*abciAPI.SubcallInfo
}

// Implements MessageDispatcher.
func (nd *testMsgDispatcher) Subscribe(any, abciAPI.MessageSubscriber) {
}

// Implements MessageDispatcher.
func (nd *testMsgDispatcher) Publish(_ *abciAPI.Context, kind, msg any) (any, error) {
	switch kind {
	case abciAPI.MessageExecuteSubcall:
		// Simulate subcall execution.
		info := msg.(*abciAPI.SubcallInfo)
		nd.delivered = append(nd.delivered, info)
		return struct{}{}, nil
	default:
		panic(fmt.Errorf("message kind '%T' not implemented in tests", kind))
	}
}

func TestAuthorizeCancelAction(t *testing.T) {
	require := require.New(t)

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	md := &testMsgDispatcher{}
	app := &vaultApplication{
		state: appState,
		md:    md,
	}

	state := vaultState.NewMutableState(ctx.State())
	err := state.SetConsensusParameters(ctx, &vault.ConsensusParameters{
		MaxAuthorityAddresses: 32,
	})
	require.NoError(err, "SetConsensusParameters")

	ctx = appState.NewContext(abciAPI.ContextDeliverTx)
	defer ctx.Close()

	// Create a vault.
	err = app.create(ctx, &vault.Create{
		AdminAuthority: vault.Authority{
			Addresses: []staking.Address{
				testAddrA,
				testAddrB,
			},
			Threshold: 2,
		},
		SuspendAuthority: vault.Authority{
			Addresses: []staking.Address{
				testAddrB,
				testAddrC,
				testAddrD,
			},
			Threshold: 3,
		},
	})
	require.NoError(err, "create")
	vaultAddr := vault.NewVaultAddress(ctx.CallerAddress(), 0)

	for _, tc := range []struct {
		msg         string
		caller      staking.Address
		args        any
		ok          bool
		expectedErr error
		afterFn     func(*abciAPI.Context)
	}{
		{
			"invalid vault should fail",
			staking.Address{},
			&vault.AuthorizeAction{
				Action: vault.Action{Suspend: &vault.ActionSuspend{}},
			},
			false,
			vault.ErrNoSuchVault,
			nil,
		},
		{
			"invalid action should fail",
			staking.Address{},
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Action: vault.Action{},
			},
			false,
			vault.ErrInvalidArgument,
			nil,
		},
		{
			"invalid nonce should fail",
			staking.Address{},
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  42,
				Action: vault.Action{Suspend: &vault.ActionSuspend{}},
			},
			false,
			vault.ErrInvalidNonce,
			nil,
		},
		{
			"invalid caller should fail",
			staking.Address{},
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  0,
				Action: vault.Action{Suspend: &vault.ActionSuspend{}},
			},
			false,
			vault.ErrForbidden,
			nil,
		},
		{
			"cancellation of a non-existing action should fail",
			testAddrA,
			&vault.CancelAction{
				Vault: vaultAddr,
				Nonce: 0,
			},
			false,
			vault.ErrNoSuchAction,
			nil,
		},
		{
			"authorizing a new action should create it",
			testAddrA,
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  0,
				Action: vault.Action{Suspend: &vault.ActionSuspend{}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var vlt *vault.Vault
				vlt, err = state.Vault(ctx, vaultAddr)
				require.NoError(err)
				require.EqualValues(0, vlt.Nonce, "nonce should not advance")
				require.True(vlt.IsActive(), "vault should not be suspended")

				var pa *vault.PendingAction
				pa, err = state.PendingAction(ctx, vaultAddr, 0)
				require.NoError(err, "pending action should be created")
				require.Len(pa.AuthorizedBy, 1)
				require.EqualValues(pa.AuthorizedBy[0], testAddrA)
			},
		},
		{
			"authorizing the same action by the same authorizer should be a no-op",
			testAddrA,
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  0,
				Action: vault.Action{Suspend: &vault.ActionSuspend{}},
			},
			true,
			nil,
			nil,
		},
		{
			"cancelling an existing action should work",
			testAddrA,
			&vault.CancelAction{
				Vault: vaultAddr,
				Nonce: 0,
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var vlt *vault.Vault
				vlt, err = state.Vault(ctx, vaultAddr)
				require.NoError(err)
				require.EqualValues(1, vlt.Nonce, "nonce should advance")
				require.True(vlt.IsActive(), "vault should not be suspended")

				_, err = state.PendingAction(ctx, vaultAddr, 0)
				require.Error(err, "pending action should no longer exist")
			},
		},
		{
			"authorizing a new action should create it (1/3)",
			testAddrA,
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  1,
				Action: vault.Action{Suspend: &vault.ActionSuspend{}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var vlt *vault.Vault
				vlt, err = state.Vault(ctx, vaultAddr)
				require.NoError(err)
				require.EqualValues(1, vlt.Nonce, "nonce should not advance")
				require.True(vlt.IsActive(), "vault should not be suspended")

				var pa *vault.PendingAction
				pa, err = state.PendingAction(ctx, vaultAddr, 1)
				require.NoError(err, "pending action should be created")
				require.Len(pa.AuthorizedBy, 1)
				require.EqualValues(pa.AuthorizedBy[0], testAddrA)
			},
		},
		{
			"authorizing a new action should update authorizer set (2/3)",
			testAddrC, // Part of suspend authority, but not admin authority.
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  1,
				Action: vault.Action{Suspend: &vault.ActionSuspend{}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var vlt *vault.Vault
				vlt, err = state.Vault(ctx, vaultAddr)
				require.NoError(err)
				require.EqualValues(1, vlt.Nonce, "nonce should not advance")
				require.True(vlt.IsActive(), "vault should not be suspended")

				var pa *vault.PendingAction
				pa, err = state.PendingAction(ctx, vaultAddr, 1)
				require.NoError(err, "pending action should be updated")
				require.Len(pa.AuthorizedBy, 2)
				require.EqualValues(pa.AuthorizedBy[0], testAddrA)
				require.EqualValues(pa.AuthorizedBy[1], testAddrC)
			},
		},
		{
			"collecting enough authorizations should execute action (3/3)",
			testAddrB,
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  1,
				Action: vault.Action{Suspend: &vault.ActionSuspend{}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var vlt *vault.Vault
				vlt, err = state.Vault(ctx, vaultAddr)
				require.NoError(err)
				require.EqualValues(2, vlt.Nonce, "nonce should advance")
				require.False(vlt.IsActive(), "vault should be suspended")

				_, err = state.PendingAction(ctx, vaultAddr, 1)
				require.Error(err, "pending action should no longer exist")
			},
		},
		{
			"action: resume (1/2)",
			testAddrA,
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  2,
				Action: vault.Action{Resume: &vault.ActionResume{}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var vlt *vault.Vault
				vlt, err = state.Vault(ctx, vaultAddr)
				require.NoError(err)
				require.EqualValues(2, vlt.Nonce, "nonce should not advance")
				require.False(vlt.IsActive(), "vault should be suspended")

				var pa *vault.PendingAction
				pa, err = state.PendingAction(ctx, vaultAddr, 2)
				require.NoError(err, "pending action should be created")
				require.Len(pa.AuthorizedBy, 1)
				require.EqualValues(pa.AuthorizedBy[0], testAddrA)
			},
		},
		{
			"action: resume (2/2)",
			testAddrB,
			&vault.AuthorizeAction{
				Vault:  vaultAddr,
				Nonce:  2,
				Action: vault.Action{Resume: &vault.ActionResume{}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var vlt *vault.Vault
				vlt, err = state.Vault(ctx, vaultAddr)
				require.NoError(err)
				require.EqualValues(3, vlt.Nonce, "nonce should advance")
				require.True(vlt.IsActive(), "vault should not be suspended")

				_, err = state.PendingAction(ctx, vaultAddr, 2)
				require.Error(err, "pending action should no longer exist")
			},
		},
		{
			"action: update withdraw policy should only be authorized by admin",
			testAddrC,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 3,
				Action: vault.Action{UpdateWithdrawPolicy: &vault.ActionUpdateWithdrawPolicy{
					Address: testAddrE,
					Policy:  vault.WithdrawPolicy{},
				}},
			},
			false,
			vault.ErrForbidden,
			nil,
		},
		{
			"action: update withdraw policy (1/2)",
			testAddrA,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 3,
				Action: vault.Action{UpdateWithdrawPolicy: &vault.ActionUpdateWithdrawPolicy{
					Address: testAddrE,
					Policy: vault.WithdrawPolicy{
						LimitAmount:   *quantity.NewFromUint64(100),
						LimitInterval: 42,
					},
				}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				_, err = state.AddressState(ctx, vaultAddr, testAddrE)
				require.ErrorIs(err, vault.ErrNoSuchState)
			},
		},
		{
			"action: update withdraw policy (2/2)",
			testAddrB,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 3,
				Action: vault.Action{UpdateWithdrawPolicy: &vault.ActionUpdateWithdrawPolicy{
					Address: testAddrE,
					Policy: vault.WithdrawPolicy{
						LimitAmount:   *quantity.NewFromUint64(100),
						LimitInterval: 42,
					},
				}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var as *vault.AddressState
				as, err = state.AddressState(ctx, vaultAddr, testAddrE)
				require.NoError(err)
				require.EqualValues(100, as.WithdrawPolicy.LimitAmount.ToBigInt().Uint64())
				require.EqualValues(42, as.WithdrawPolicy.LimitInterval)
			},
		},
		{
			"action: update authority should only be authorized by admin",
			testAddrC,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 4,
				Action: vault.Action{UpdateAuthority: &vault.ActionUpdateAuthority{
					SuspendAuthority: &vault.Authority{
						Addresses: []staking.Address{
							testAddrB,
							testAddrC,
						},
						Threshold: 2,
					},
				}},
			},
			false,
			vault.ErrForbidden,
			nil,
		},
		{
			"action: update authority (1/2)",
			testAddrA,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 4,
				Action: vault.Action{UpdateAuthority: &vault.ActionUpdateAuthority{
					SuspendAuthority: &vault.Authority{
						Addresses: []staking.Address{
							testAddrB,
							testAddrC,
						},
						Threshold: 2,
					},
				}},
			},
			true,
			nil,
			nil,
		},
		{
			"action: update authority (2/2)",
			testAddrB,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 4,
				Action: vault.Action{UpdateAuthority: &vault.ActionUpdateAuthority{
					SuspendAuthority: &vault.Authority{
						Addresses: []staking.Address{
							testAddrB,
							testAddrC,
						},
						Threshold: 2,
					},
				}},
			},
			true,
			nil,
			func(ctx *abciAPI.Context) {
				var vlt *vault.Vault
				vlt, err = state.Vault(ctx, vaultAddr)
				require.NoError(err)
				require.Len(vlt.SuspendAuthority.Addresses, 2)
				require.EqualValues(testAddrB, vlt.SuspendAuthority.Addresses[0])
				require.EqualValues(testAddrC, vlt.SuspendAuthority.Addresses[1])
				require.EqualValues(2, vlt.SuspendAuthority.Threshold)
			},
		},
		{
			"action: execute message should only be authorized by admin",
			testAddrC,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 5,
				Action: vault.Action{ExecuteMessage: &vault.ActionExecuteMessage{
					Method: "foo.Bar",
				}},
			},
			false,
			vault.ErrForbidden,
			nil,
		},
		{
			"action: execute message (1/2)",
			testAddrA,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 5,
				Action: vault.Action{ExecuteMessage: &vault.ActionExecuteMessage{
					Method: "foo.Bar",
				}},
			},
			true,
			nil,
			nil,
		},
		{
			"action: execute message (2/2)",
			testAddrB,
			&vault.AuthorizeAction{
				Vault: vaultAddr,
				Nonce: 5,
				Action: vault.Action{ExecuteMessage: &vault.ActionExecuteMessage{
					Method: "foo.Bar",
				}},
			},
			true,
			nil,
			func(*abciAPI.Context) {
				require.Len(md.delivered, 1)
				require.EqualValues("foo.Bar", md.delivered[0].Method)
				require.EqualValues(vaultAddr, md.delivered[0].Caller)
			},
		},
	} {
		ctx = appState.NewContext(abciAPI.ContextDeliverTx).WithCallerAddress(tc.caller)
		defer ctx.Close()

		switch args := tc.args.(type) {
		case *vault.AuthorizeAction:
			err = app.authorizeAction(ctx, args)
		case *vault.CancelAction:
			err = app.cancelAction(ctx, args)
		default:
			panic("unsupported argument type")
		}
		switch tc.ok {
		case false:
			require.ErrorIs(err, tc.expectedErr, tc.msg)
		case true:
			require.NoError(err, tc.msg)
		}

		if tc.afterFn != nil {
			(tc.afterFn)(ctx)
		}
	}
}
