package vault

import (
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// executeAction executes a given action in the context of a vault. Assumes the action has already
// been validated before execution.
func (app *Application) executeAction(ctx *api.Context, vlt *vault.Vault, action *vault.Action) error {
	switch {
	case action.Suspend != nil:
		// Suspend a vault.
		oldState := vlt.State
		vlt.State = vault.StateSuspended
		if oldState == vlt.State {
			return nil
		}

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&vault.StateChangedEvent{
			Vault:    vlt.Address(),
			OldState: oldState,
			NewState: vlt.State,
		}))
	case action.Resume != nil:
		// Resume a vault.
		oldState := vlt.State
		vlt.State = vault.StateActive
		if oldState == vlt.State {
			return nil
		}

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&vault.StateChangedEvent{
			Vault:    vlt.Address(),
			OldState: oldState,
			NewState: vlt.State,
		}))
	case action.UpdateWithdrawPolicy != nil:
		// Update withdraw policy for an address.
		state := vaultState.NewMutableState(ctx.State())
		addrState, err := state.AddressState(ctx, vlt.Address(), action.UpdateWithdrawPolicy.Address)
		switch err {
		case nil:
		case vault.ErrNoSuchState:
			addrState = &vault.AddressState{}
		default:
			return err
		}

		addrState.UpdateWithdrawPolicy(&action.UpdateWithdrawPolicy.Policy)
		if err = state.SetAddressState(ctx, vlt.Address(), action.UpdateWithdrawPolicy.Address, addrState); err != nil {
			return err
		}

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&vault.PolicyUpdatedEvent{
			Vault:   vlt.Address(),
			Address: action.UpdateWithdrawPolicy.Address,
		}))
	case action.UpdateAuthority != nil:
		// Update a vault authority.
		state := vaultState.NewMutableState(ctx.State())
		params, err := state.ConsensusParameters(ctx)
		if err != nil {
			return err
		}
		// Ensure the authority is still valid, e.g. in case parameters have changed.
		if err = action.UpdateAuthority.Validate(params); err != nil {
			return err
		}

		action.UpdateAuthority.Apply(vlt)

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&vault.AuthorityUpdatedEvent{
			Vault: vlt.Address(),
		}))
	case action.ExecuteMessage != nil:
		// Execute a message with vault as the caller.
		_, err := app.md.Publish(ctx, api.MessageExecuteSubcall, &api.SubcallInfo{
			Caller: vlt.Address(),
			Method: action.ExecuteMessage.Method,
			Body:   action.ExecuteMessage.Body,
		})
		return err
	default:
		return vault.ErrUnsupportedAction
	}
	return nil
}
