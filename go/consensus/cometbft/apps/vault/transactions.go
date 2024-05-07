package vault

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

func (app *vaultApplication) create(ctx *api.Context, create *vault.Create) error {
	state := vaultState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	if err = create.Validate(params); err != nil {
		return fmt.Errorf("%w: %w", vault.ErrInvalidArgument, err)
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	if err = ctx.Gas().UseGas(1, vault.GasOpCreate, params.GasCosts); err != nil {
		return err
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	// Start a new transaction and rollback in case we fail.
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	// Determine caller nonce.
	stakeState := stakingState.NewMutableState(ctx.State())
	callerAcct, err := stakeState.Account(ctx, ctx.CallerAddress())
	if err != nil {
		return err
	}

	// Create a new vault.
	newVault := &vault.Vault{
		State:            vault.StateActive,
		Nonce:            0,
		Creator:          ctx.CallerAddress(),
		ID:               callerAcct.General.Nonce,
		AdminAuthority:   create.AdminAuthority,
		SuspendAuthority: create.SuspendAuthority,
	}
	if err = state.CreateVault(ctx, newVault); err != nil {
		return err
	}

	ctx.Commit()

	return nil
}

func (app *vaultApplication) authorizeAction(ctx *api.Context, authAction *vault.AuthorizeAction) error {
	state := vaultState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	if err = authAction.Validate(params); err != nil {
		return fmt.Errorf("%w: %w", vault.ErrInvalidArgument, err)
	}

	// Ensure vault exists.
	vlt, err := state.Vault(ctx, authAction.Vault)
	if err != nil {
		return err
	}

	// Validate action nonce. Currently queuing multiple future actions is not allowed.
	if authAction.Nonce != vlt.Nonce {
		return vault.ErrInvalidNonce
	}

	// Validate whether the caller is authorized to submit an action.
	if !authAction.Action.IsAuthorized(vlt, ctx.CallerAddress()) {
		return vault.ErrForbidden
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	if err = ctx.Gas().UseGas(1, vault.GasOpAuthorizeAction, params.GasCosts); err != nil {
		return err
	}

	// Start a new transaction and rollback in case we fail.
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	// Check if there is an existing pending action for this nonce. In this case, we will be
	// updating the action.
	pendingAction, err := state.PendingAction(ctx, authAction.Vault, authAction.Nonce)
	switch err {
	case nil:
		// Ensure that the action is the same so that the authorizer really signed the correct
		// action.
		if !pendingAction.Action.Equal(&authAction.Action) {
			return vault.ErrInvalidArgument
		}
	case vault.ErrNoSuchAction:
		// Create a new pending action.
		pendingAction = &vault.PendingAction{
			Nonce:  authAction.Nonce,
			Action: authAction.Action,
		}
	default:
		return err
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&vault.ActionSubmittedEvent{
		Submitter: ctx.CallerAddress(),
		Vault:     authAction.Vault,
		Nonce:     authAction.Nonce,
	}))

	// Update list of authorizers.
	if !pendingAction.ContainsAuthorizationFrom(ctx.CallerAddress()) {
		pendingAction.AuthorizedBy = append(pendingAction.AuthorizedBy, ctx.CallerAddress())
		if err = state.SetPendingAction(ctx, authAction.Vault, pendingAction); err != nil {
			return err
		}
	}

	// Check if action has become executable.
	var canExecute bool
	for _, auth := range pendingAction.Action.Authorities(vlt) {
		if auth.Verify(pendingAction.AuthorizedBy) {
			canExecute = true
			break
		}
	}
	if !canExecute {
		ctx.Commit()
		return nil
	}

	// Execute action.
	evExec := &vault.ActionExecutedEvent{
		Vault: authAction.Vault,
		Nonce: authAction.Nonce,
	}
	err = app.executeAction(ctx, vlt, &pendingAction.Action)
	switch {
	case api.IsUnavailableStateError(err):
		// Propagate state unavailability errors.
		return err
	default:
		// Record other errors (or success) in the execution event.
		evExec.Result.Module, evExec.Result.Code = errors.Code(err)

		ctx.Logger().Debug("vault executed action",
			"err", err,
			"vault", authAction.Vault,
			"nonce", authAction.Nonce,
			"action", pendingAction.Action,
		)
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(evExec))

	// Remove pending action as it has been executed.
	if err = state.RemovePendingAction(ctx, authAction.Vault, authAction.Nonce); err != nil {
		return err
	}

	vlt.Nonce++
	if err = state.SetVault(ctx, vlt); err != nil {
		return err
	}

	ctx.Commit()

	return nil
}

func (app *vaultApplication) cancelAction(ctx *api.Context, cancelAction *vault.CancelAction) error {
	// Validate arguments.
	if err := cancelAction.Validate(); err != nil {
		return fmt.Errorf("%w: %w", vault.ErrInvalidArgument, err)
	}

	// Ensure vault exists.
	state := vaultState.NewMutableState(ctx.State())
	vlt, err := state.Vault(ctx, cancelAction.Vault)
	if err != nil {
		return err
	}

	// Validate action nonce. Currently queuing multiple future actions is not allowed.
	if cancelAction.Nonce != vlt.Nonce {
		return vault.ErrInvalidNonce
	}

	// Before we know what the canceled action is, we can only check that the caller is part of at
	// least one of the vault's authorities. Later, we will check against the action authority.
	if !vlt.AuthoritiesContain(ctx.CallerAddress()) {
		return vault.ErrForbidden
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if err = ctx.Gas().UseGas(1, vault.GasOpCancelAction, params.GasCosts); err != nil {
		return err
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	// Start a new transaction and rollback in case we fail.
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	// Fetch the action that is being canceled.
	pendingAction, err := state.PendingAction(ctx, cancelAction.Vault, cancelAction.Nonce)
	if err != nil {
		return err
	}

	// Perform action-specific authority check now that we know what the action is.
	if !pendingAction.Action.IsAuthorized(vlt, ctx.CallerAddress()) {
		return vault.ErrForbidden
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&vault.ActionCanceledEvent{
		Vault: cancelAction.Vault,
		Nonce: cancelAction.Nonce,
	}))

	if err = state.RemovePendingAction(ctx, cancelAction.Vault, cancelAction.Nonce); err != nil {
		return err
	}

	vlt.Nonce++
	if err = state.SetVault(ctx, vlt); err != nil {
		return err
	}

	ctx.Commit()

	return nil
}
