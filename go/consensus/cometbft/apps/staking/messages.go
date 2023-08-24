package staking

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
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

	// Do any necessary state migrations.
	if changes.MinCommissionRate != nil && apply {
		var epoch beacon.EpochTime
		epoch, err = ctx.AppState().GetCurrentEpoch(ctx)
		if err != nil {
			return nil, fmt.Errorf("staking: failed to load epoch")
		}
		// On MinCommissionRate update, the staking state needs to be updated to ensure all
		// commission rates and bounds are above the new min commission rate.
		var addresses []staking.Address
		addresses, err = state.CommissionScheduleAddresses(ctx)
		if err != nil {
			return nil, fmt.Errorf("staking: failed to load addresses: %w", err)
		}
		for _, addr := range addresses {
			var acc *staking.Account
			acc, err = state.Account(ctx, addr)
			if err != nil {
				return nil, fmt.Errorf("staking: failed to load account: %w", err)
			}
			var updated bool
			for i, bound := range acc.Escrow.CommissionSchedule.Bounds {
				if changes.MinCommissionRate.Cmp(&bound.RateMin) > 0 { //nolint:gosec
					// Update the minimum rate bound, to be at least the minimum bound.
					acc.Escrow.CommissionSchedule.Bounds[i].RateMin = *changes.MinCommissionRate.Clone()
					updated = true
				}
				if changes.MinCommissionRate.Cmp(&bound.RateMax) > 0 { //nolint:gosec
					// Update the maximum rate bound, to be at least the minimum bound.
					acc.Escrow.CommissionSchedule.Bounds[i].RateMax = *changes.MinCommissionRate.Clone()
					updated = true
				}
			}
			for i, rate := range acc.Escrow.CommissionSchedule.Rates {
				if changes.MinCommissionRate.Cmp(&rate.Rate) > 0 { //nolint:gosec
					// Update the rate, to be at least the minimum bound.
					acc.Escrow.CommissionSchedule.Rates[i].Rate = *changes.MinCommissionRate.Clone()
					updated = true
				}
			}
			if updated {
				// Validate updated commission schedule. Also prunes old, unused rules.
				if err = acc.Escrow.CommissionSchedule.PruneAndValidate(&params.CommissionScheduleRules, epoch); err != nil {
					return nil, fmt.Errorf("staking: commission schedule for account '%s' invalid after update: %w", addr, err)
				}
				if err = state.SetAccount(ctx, addr, acc); err != nil {
					return nil, fmt.Errorf("staking: failed to store account '%s': %w", addr, err)
				}
			}

		}
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
