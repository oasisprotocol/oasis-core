package vault

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/api"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

func (app *Application) changeParameters(ctx *api.Context, msg any, apply bool) (any, error) {
	// Unmarshal changes and check if they should be applied to this module.
	proposal, ok := msg.(*governance.ChangeParametersProposal)
	if !ok {
		return nil, fmt.Errorf("cometbft/vault: failed to type assert change parameters proposal")
	}

	if proposal.Module != vault.ModuleName {
		return nil, nil
	}

	var changes vault.ConsensusParameterChanges
	if err := cbor.Unmarshal(proposal.Changes, &changes); err != nil {
		return nil, fmt.Errorf("cometbft/vault: failed to unmarshal consensus parameter changes: %w", err)
	}

	// Validate changes against current parameters.
	state := vaultState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("cometbft/vault: failed to load consensus parameters: %w", err)
	}
	if err = changes.SanityCheck(); err != nil {
		return nil, fmt.Errorf("cometbft/vault: failed to validate consensus parameter changes: %w", err)
	}
	if err = changes.Apply(params); err != nil {
		return nil, fmt.Errorf("cometbft/vault: failed to apply consensus parameter changes: %w", err)
	}
	if err = params.SanityCheck(); err != nil {
		return nil, fmt.Errorf("cometbft/vault: failed to validate consensus parameters: %w", err)
	}

	// Apply changes.
	if apply {
		if err = state.SetConsensusParameters(ctx, params); err != nil {
			return nil, fmt.Errorf("cometbft/vault: failed to update consensus parameters: %w", err)
		}
	}

	// Non-nil response signals that changes are valid and were successfully applied (if required).
	return struct{}{}, nil
}

// invokeAccountHook processes an account hook invocation.
func (app *Application) invokeAccountHook(ctx *api.Context, msg any) (any, error) {
	ahi, ok := msg.(stakingApi.AccountHookInvocation)
	if !ok {
		return nil, nil
	}
	if !ahi.DestinationMatches(staking.HookDestination{Module: vault.ModuleName}) {
		return nil, nil
	}

	state := vaultState.NewMutableState(ctx.State())

	switch hi := ahi.(type) {
	case *stakingApi.WithdrawHookInvocation:
		// Withdrawal from vault, check if authorized.
		vlt, err := state.Vault(ctx, hi.From)
		if err != nil {
			return nil, err
		}
		if !vlt.IsActive() {
			return nil, vault.ErrForbidden
		}

		as, err := state.AddressState(ctx, hi.From, hi.To)
		if err != nil {
			return nil, err
		}
		if !as.AuthorizeWithdrawal(ctx.BlockHeight()+1, hi.Amount) {
			return nil, vault.ErrForbidden
		}

		// Update address state.
		if err = state.SetAddressState(ctx, hi.From, hi.To, as); err != nil {
			return nil, err
		}

		// Withdrawal is allowed.
		return struct{}{}, nil
	default:
		return nil, nil
	}
}
