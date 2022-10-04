package governance

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func (app *governanceApplication) completeStateSync(ctx *api.Context) (interface{}, error) {
	// State sync has just completed, check whether there are any pending upgrades to make
	// sure we don't miss them after the sync.
	state := governanceState.NewMutableState(ctx.State())
	pendingUpgrades, err := state.PendingUpgrades(ctx)
	if err != nil {
		return nil, fmt.Errorf("tendermint/governance: couldn't get pending upgrades: %w", err)
	}

	// Apply all pending upgrades locally.
	if upgrader := ctx.AppState().Upgrader(); upgrader != nil {
		for _, pu := range pendingUpgrades {
			switch err = upgrader.SubmitDescriptor(ctx, pu); err {
			case nil, upgrade.ErrAlreadyPending:
			default:
				ctx.Logger().Error("failed to locally apply the upgrade descriptor",
					"err", err,
					"descriptor", pu,
				)
			}
		}
	}
	// No execute message results at this time.
	return nil, nil
}

func (app *governanceApplication) changeParameters(ctx *api.Context, msg interface{}, apply bool) (interface{}, error) {
	// Unmarshal changes and check if they should be applied to this module.
	proposal, ok := msg.(*governance.ChangeParametersProposal)
	if !ok {
		return nil, fmt.Errorf("tendermint/governance: failed to type assert change parameters proposal")
	}

	if proposal.Module != governance.ModuleName {
		return nil, nil
	}

	var changes governance.ConsensusParameterChanges
	if err := cbor.Unmarshal(proposal.Changes, &changes); err != nil {
		return nil, fmt.Errorf("tendermint/governance: failed to unmarshal consensus parameter changes: %w", err)
	}

	// Validate changes against current parameters.
	state := governanceState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("tendermint/governance: failed to load consensus parameters: %w", err)
	}
	if err = changes.SanityCheck(); err != nil {
		return nil, fmt.Errorf("tendermint/governance: failed to validate consensus parameter changes: %w", err)
	}
	if err = changes.Apply(params); err != nil {
		return nil, fmt.Errorf("tendermint/governance: failed to apply consensus parameter changes: %w", err)
	}
	if err = params.SanityCheck(); err != nil {
		return nil, fmt.Errorf("tendermint/governance: failed to validate consensus parameters: %w", err)
	}

	// Apply changes.
	if apply {
		if err = state.SetConsensusParameters(ctx, params); err != nil {
			return nil, fmt.Errorf("tendermint/governance: failed to update consensus parameters: %w", err)
		}
	}

	// Non-nil response signals that changes are valid and were successfully applied (if required).
	return struct{}{}, nil
}
