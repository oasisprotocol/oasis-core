package state

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

func TestBasic(t *testing.T) {
	require := require.New(t)

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	state := NewMutableState(ctx.State())

	params, err := state.ConsensusParameters(ctx)
	require.NoError(err, "ConsensusParameters")
	require.EqualValues(&vault.ConsensusParameters{}, params)

	vault1 := &vault.Vault{
		ID: 0,
	}
	err = state.CreateVault(ctx, vault1)
	require.NoError(err, "CreateVault")
	err = state.CreateVault(ctx, vault1)
	require.Error(err, "CreateVault should fail when vault already exists")

	vlt, err := state.Vault(ctx, vault1.Address())
	require.NoError(err, "Vault")
	require.EqualValues(vault1, vlt)

	vault2 := &vault.Vault{
		ID: 1,
	}
	err = state.CreateVault(ctx, vault2)
	require.NoError(err, "CreateVault")

	vlt, err = state.Vault(ctx, vault2.Address())
	require.NoError(err, "Vault")
	require.EqualValues(vault2, vlt)

	vaults, err := state.Vaults(ctx)
	require.NoError(err, "Vaults")
	require.Len(vaults, 2, "there should be two vaults")

	states, err := state.AddressStates(ctx, vlt.Address())
	require.NoError(err, "AddressStates")
	require.Len(states, 0, "address states should be empty")

	pendingActions, err := state.PendingActions(ctx, vlt.Address())
	require.NoError(err, "PendingActions")
	require.Len(pendingActions, 0, "pending actions should be empty")

	testAddr1 := staking.NewModuleAddress("test", "foo")
	addrState := &vault.AddressState{
		WithdrawPolicy: vault.WithdrawPolicy{
			LimitAmount:   *quantity.NewFromUint64(1234),
			LimitInterval: 42,
		},
	}
	err = state.SetAddressState(ctx, vlt.Address(), testAddr1, addrState)
	require.NoError(err, "SetAddressState")
	states, err = state.AddressStates(ctx, vlt.Address())
	require.NoError(err, "AddressStates")
	require.Len(states, 1)
	decState, err := state.AddressState(ctx, vlt.Address(), testAddr1)
	require.NoError(err, "AddressState")
	require.EqualValues(addrState, decState)

	require.EqualValues(addrState, states[testAddr1])
	states, err = state.AddressStates(ctx, vault1.Address())
	require.NoError(err, "AddressStates")
	require.Len(states, 0)
	_, err = state.AddressState(ctx, vault1.Address(), testAddr1)
	require.Error(err, "AddressState")

	action := &vault.PendingAction{
		Nonce: 42,
	}
	err = state.SetPendingAction(ctx, vlt.Address(), action)
	require.NoError(err, "SetPendingAction")
	actions, err := state.PendingActions(ctx, vlt.Address())
	require.NoError(err, "PendingActions")
	require.Len(actions, 1)
	require.EqualValues(action, actions[0])
	decAction, err := state.PendingAction(ctx, vlt.Address(), 42)
	require.NoError(err, "PendingAction")
	require.EqualValues(action, decAction)
	_, err = state.PendingAction(ctx, vlt.Address(), 1)
	require.Error(err, "PendingAction")

	actions, err = state.PendingActions(ctx, vault1.Address())
	require.NoError(err, "PendingActions")
	require.Len(actions, 0)

	newParams := &vault.ConsensusParameters{Enabled: true}
	err = state.SetConsensusParameters(ctx, newParams)
	require.NoError(err, "SetConsensusParameters")
	params, err = state.ConsensusParameters(ctx)
	require.NoError(err, "ConsensusParameters")
	require.EqualValues(newParams, params, "consensus parameters should be correctly updated")
}
