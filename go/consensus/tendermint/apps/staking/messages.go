package staking

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *stakingApplication) changeParameters(ctx *api.Context, msg interface{}, apply bool) (interface{}, error) {
	proposal, ok := msg.(*governance.ChangeParametersProposal)
	if !ok {
		return nil, fmt.Errorf("staking: failed to type assert change parameters proposal")
	}

	if proposal.Module != staking.ModuleName {
		return nil, nil
	}

	var changes staking.ConsensusParameterChanges
	if err := cbor.Unmarshal(proposal.Changes, &changes); err != nil {
		return nil, fmt.Errorf("staking: failed to unmarshal consensus parameter changes: %w", err)
	}

	// Validate and apply changes to the parameters.
	state := stakingState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("staking: failed to load consensus parameters: %w", err)
	}
	if err = changes.SanityCheck(); err != nil {
		return nil, fmt.Errorf("staking: failed to validate consensus parameter changes: %w", err)
	}
	if err = changes.Apply(params); err != nil {
		return nil, fmt.Errorf("staking: failed to apply consensus parameter changes: %w", err)
	}
	if err = params.SanityCheck(); err != nil {
		return nil, fmt.Errorf("staking: failed to validate consensus parameters: %w", err)
	}

	// Apply changes.
	if apply {
		if err = state.SetConsensusParameters(ctx, params); err != nil {
			return nil, fmt.Errorf("staking: failed to update consensus parameters: %w", err)
		}
	}

	// Non-nil response signals that changes are valid and were successfully applied (if required).
	return struct{}{}, nil
}
