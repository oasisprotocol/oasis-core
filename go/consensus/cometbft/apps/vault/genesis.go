package vault

import (
	"context"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

func (app *vaultApplication) InitChain(ctx *abciAPI.Context, _ types.RequestInitChain, doc *genesis.Document) error {
	st := doc.Vault
	if st == nil {
		return nil
	}

	state := vaultState.NewMutableState(ctx.State())
	if err := state.SetConsensusParameters(ctx, &st.Parameters); err != nil {
		return fmt.Errorf("cometbft/vault: failed to set consensus parameters: %w", err)
	}

	// Insert vaults.
	for _, vault := range st.Vaults {
		if err := state.SetVault(ctx, vault); err != nil {
			return err
		}
	}

	// Insert address states.
	for vaultAddr, vaultStates := range st.States {
		for addr, as := range vaultStates {
			if err := state.SetAddressState(ctx, vaultAddr, addr, as); err != nil {
				return err
			}
		}
	}

	// Insert pending actions.
	for vaultAddr, pendingActions := range st.PendingActions {
		for _, action := range pendingActions {
			if err := state.SetPendingAction(ctx, vaultAddr, action); err != nil {
				return err
			}
		}
	}

	return nil
}

// Genesis exports current state in genesis format.
func (q *vaultQuerier) Genesis(ctx context.Context) (*vault.Genesis, error) {
	params, err := q.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	// Vaults.
	vaults, err := q.state.Vaults(ctx)
	if err != nil {
		return nil, err
	}

	// Account states and pending actions.
	pendingActions := make(map[staking.Address][]*vault.PendingAction)
	states := make(map[staking.Address]map[staking.Address]*vault.AddressState)
	for _, vlt := range vaults {
		var actions []*vault.PendingAction
		actions, err = q.state.PendingActions(ctx, vlt.Address())
		if err != nil {
			return nil, err
		}

		var vaultStates map[staking.Address]*vault.AddressState
		vaultStates, err := q.state.AddressStates(ctx, vlt.Address())
		if err != nil {
			return nil, err
		}

		if len(actions) > 0 {
			pendingActions[vlt.Address()] = actions
		}
		if len(vaultStates) > 0 {
			states[vlt.Address()] = vaultStates
		}
	}

	return &vault.Genesis{
		Parameters:     *params,
		Vaults:         vaults,
		PendingActions: pendingActions,
		States:         states,
	}, nil
}
