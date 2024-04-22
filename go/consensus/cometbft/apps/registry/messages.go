package registry

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func (app *registryApplication) changeParameters(ctx *api.Context, msg interface{}, apply bool) (interface{}, error) {
	// Unmarshal changes and check if they should be applied to this module.
	proposal, ok := msg.(*governance.ChangeParametersProposal)
	if !ok {
		return nil, fmt.Errorf("registry: failed to type assert change parameters proposal")
	}

	if proposal.Module != registry.ModuleName {
		return nil, nil
	}

	var changes registry.ConsensusParameterChanges
	if err := cbor.Unmarshal(proposal.Changes, &changes); err != nil {
		return nil, fmt.Errorf("registry: failed to unmarshal consensus parameter changes: %w", err)
	}

	// Validate changes against current parameters.
	state := registryState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("registry: failed to load consensus parameters: %w", err)
	}
	if err = changes.SanityCheck(); err != nil {
		return nil, fmt.Errorf("registry: failed to validate consensus parameter changes: %w", err)
	}
	if err = changes.Apply(params); err != nil {
		return nil, fmt.Errorf("registry: failed to apply consensus parameter changes: %w", err)
	}
	if err = params.SanityCheck(); err != nil {
		return nil, fmt.Errorf("registry: failed to validate consensus parameters: %w", err)
	}

	// Apply changes.
	if apply {
		if err = state.SetConsensusParameters(ctx, params); err != nil {
			return nil, fmt.Errorf("registry: failed to update consensus parameters: %w", err)
		}
	}

	// Non-nil response signals that changes are valid and were successfully applied (if required).
	return struct{}{}, nil
}

func (app *registryApplication) requestGasPriceExemption(ctx *api.Context) (bool, error) {
	// If a node exists and is not expired this means that it must have at least some stake so it
	// can be exempt from minimum gas price requirements.
	state := registryState.NewMutableState(ctx.State())
	node, err := state.Node(ctx, ctx.TxSigner())
	if err != nil {
		return false, nil
	}

	currentEpoch, err := ctx.AppState().GetCurrentEpoch(ctx)
	if err != nil {
		return false, nil
	}
	if node.IsExpired(uint64(currentEpoch)) {
		return false, nil
	}

	// Node is registered and not expired.

	return true, nil
}
