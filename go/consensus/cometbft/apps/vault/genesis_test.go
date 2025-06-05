package vault

import (
	"testing"

	"github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	"github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

func createTestGenesis() *vault.Genesis {
	return &vault.Genesis{
		Parameters: vault.ConsensusParameters{
			Enabled:               true,
			MaxAuthorityAddresses: 32,
		},
		Vaults: []*vault.Vault{
			{
				Creator: testAddrA,
				ID:      42,
				State:   vault.StateActive,
				Nonce:   1,
				AdminAuthority: vault.Authority{
					Addresses: []staking.Address{
						testAddrA,
						testAddrB,
					},
					Threshold: 2,
				},
				SuspendAuthority: vault.Authority{
					Addresses: []staking.Address{
						testAddrA,
						testAddrB,
						testAddrC,
					},
					Threshold: 1,
				},
			},
			{
				Creator: testAddrA,
				ID:      45,
				State:   vault.StateSuspended,
				Nonce:   2,
				AdminAuthority: vault.Authority{
					Addresses: []staking.Address{
						testAddrA,
					},
					Threshold: 1,
				},
				SuspendAuthority: vault.Authority{
					Addresses: []staking.Address{
						testAddrB,
						testAddrD,
					},
					Threshold: 2,
				},
			},
		},
		States: map[staking.Address]map[staking.Address]*vault.AddressState{
			vault.NewVaultAddress(testAddrA, 42): {
				testAddrA: {
					CurrentBucket: 10,
					CurrentAmount: *quantity.NewFromUint64(100),
				},
			},
		},
		PendingActions: map[staking.Address][]*vault.PendingAction{
			vault.NewVaultAddress(testAddrA, 45): {
				{
					Nonce:        0,
					AuthorizedBy: []staking.Address{testAddrB},
					Action:       vault.Action{Resume: &vault.ActionResume{}},
				},
			},
		},
	}
}

func TestInitChain(t *testing.T) {
	require := require.New(t)
	var err error

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextInitChain)
	defer ctx.Close()

	state := vaultState.NewMutableState(ctx.State())
	app := &Application{
		state: appState,
	}

	for _, tc := range []struct {
		msg        string
		genesisDoc *api.Document
		check      func()
	}{
		{
			"should correctly initialize empty state",
			&api.Document{Vault: nil},
			func() {
				var params *vault.ConsensusParameters
				params, err = state.ConsensusParameters(ctx)
				require.NoError(err, "ConsensusParameters")
				require.Equal(false, params.Enabled)

				var vaults []*vault.Vault
				vaults, err = state.Vaults(ctx)
				require.NoError(err, "Vaults")
				require.Empty(vaults, "no vaults should exist")
			},
		},
		{
			"should correctly initialize state",
			&api.Document{
				Vault: createTestGenesis(),
			},
			func() {
				var params *vault.ConsensusParameters
				params, err = state.ConsensusParameters(ctx)
				require.NoError(err, "ConsensusParameters")
				require.EqualValues(true, params.Enabled)
				require.EqualValues(32, params.MaxAuthorityAddresses)

				var vaults []*vault.Vault
				vaults, err = state.Vaults(ctx)
				require.NoError(err, "Vaults")
				require.Len(vaults, 2, "vaults should be correctly initialized")

				require.EqualValues(testAddrA, vaults[0].Creator)
				require.EqualValues(45, vaults[0].ID)
				require.EqualValues(vault.StateSuspended, vaults[0].State)
				require.EqualValues(2, vaults[0].Nonce)

				require.EqualValues(testAddrA, vaults[1].Creator)
				require.EqualValues(42, vaults[1].ID)
				require.EqualValues(vault.StateActive, vaults[1].State)
				require.EqualValues(1, vaults[1].Nonce)

				var addrStates map[staking.Address]*vault.AddressState
				addrStates, err = state.AddressStates(ctx, vaults[1].Address())
				require.NoError(err, "AddressStates")
				require.Len(addrStates, 1, "address states should be correctly initialized")
				require.EqualValues(10, addrStates[testAddrA].CurrentBucket)
				require.EqualValues(100, addrStates[testAddrA].CurrentAmount.ToBigInt().Uint64())

				var pendingActions []*vault.PendingAction
				pendingActions, err = state.PendingActions(ctx, vaults[0].Address())
				require.NoError(err, "PendingActions")
				require.Len(pendingActions, 1, "pending actions should be correctly initialized")
				require.EqualValues(0, pendingActions[0].Nonce)
				require.EqualValues([]staking.Address{testAddrB}, pendingActions[0].AuthorizedBy)
			},
		},
	} {
		err = app.InitChain(ctx, types.RequestInitChain{}, tc.genesisDoc)
		require.NoError(err, tc.msg)
		tc.check()
	}
}

func TestGenesis(t *testing.T) {
	require := require.New(t)
	var err error

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	state := vaultState.NewMutableState(ctx.State())
	testGenesis := createTestGenesis()

	for _, tc := range []struct {
		msg             string
		init            func()
		expectedGenesis vault.Genesis
	}{
		{
			"should correctly export genesis from empty state",
			func() {},
			vault.Genesis{
				Vaults:         nil,
				States:         make(map[staking.Address]map[staking.Address]*vault.AddressState),
				PendingActions: make(map[staking.Address][]*vault.PendingAction),
			},
		},
		{
			"should correctly export genesis",
			func() {
				// Prepare state that should be exported into the expected genesis.
				err = state.SetConsensusParameters(ctx, &testGenesis.Parameters)
				require.NoError(err, "ConsensusParameters")

				for _, vlt := range testGenesis.Vaults {
					err = state.SetVault(ctx, vlt)
					require.NoError(err, "SetVault")
				}
				for vltAddr, addrStates := range testGenesis.States {
					for addr, addrState := range addrStates {
						err = state.SetAddressState(ctx, vltAddr, addr, addrState)
						require.NoError(err, "SetAddressState")
					}
				}
				for vltAddr, pendingActions := range testGenesis.PendingActions {
					for _, pa := range pendingActions {
						err = state.SetPendingAction(ctx, vltAddr, pa)
						require.NoError(err, "SetPendingAction")
					}
				}
			},
			*testGenesis,
		},
	} {
		tc.init()

		qf := NewQueryFactory(appState)
		var q *Query
		// Need to use blockHeight+1, so that request is treated like it was
		// made from an ABCI application context.
		q, err = qf.QueryAt(ctx, 1)
		require.NoError(err, "QueryAt")

		var g *vault.Genesis
		g, err = q.Genesis(ctx)
		require.NoError(err, tc.msg)

		require.Equal(tc.expectedGenesis.Parameters, g.Parameters, tc.msg)
		require.ElementsMatch(tc.expectedGenesis.Vaults, g.Vaults, tc.msg)

		require.Len(g.States, len(tc.expectedGenesis.States))
		for vltAddr, addrStates := range g.States {
			require.Len(addrStates, len(tc.expectedGenesis.States[vltAddr]))
			for addr, addrState := range addrStates {
				require.Equal(tc.expectedGenesis.States[vltAddr][addr], addrState)
			}
		}

		require.Len(g.PendingActions, len(tc.expectedGenesis.PendingActions))
		for vltAddr, pendingActions := range g.PendingActions {
			require.ElementsMatch(tc.expectedGenesis.PendingActions[vltAddr], pendingActions)
		}
	}
}
