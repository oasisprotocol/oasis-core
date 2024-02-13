package churp

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/common"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

func (ext *churpExt) create(ctx *tmapi.Context, req *churp.CreateRequest) error {
	// Prepare state.
	state := churpState.NewMutableState(ctx.State())

	// Ensure that the runtime exists and is a key manager.
	kmRt, err := common.KeyManagerRuntime(ctx, req.RuntimeID)
	if err != nil {
		return err
	}

	// Ensure that the tx signer is the key manager owner.
	if !kmRt.EntityID.Equal(ctx.TxSigner()) {
		return fmt.Errorf("keymanager: churp: invalid signer")
	}

	// Make sure the ID is unique.
	_, err = state.Status(ctx, req.RuntimeID, req.ID)
	switch err {
	case nil:
		return fmt.Errorf("keymanager: churp: invalid config: ID must be unique")
	case churp.ErrNoSuchStatus:
	default:
		return err
	}

	// Verify data.
	if err = req.ValidateBasic(); err != nil {
		return fmt.Errorf("keymanager: churp: invalid config: %w", err)
	}
	if err = req.Policy.SanityCheck(nil); err != nil {
		return fmt.Errorf("keymanager: churp: invalid config: %w", err)
	}

	// Compute epoch of the first handoff.
	var nextHandoff beacon.EpochTime
	switch req.HandoffInterval {
	case 0:
		nextHandoff = churp.HandoffsDisabled
	default:
		// Schedule the first epoch.
		nextHandoff, err = ext.computeNextHandoff(ctx)
		if err != nil {
			return err
		}
	}

	// TODO: Add stake claim.

	// Return early if this is a CheckTx context.
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this operation.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, churp.GasOpCreate, params.GasCosts); err != nil {
		return err
	}

	// Return early if simulating since this is just estimating gas.
	if ctx.IsSimulation() {
		return nil
	}

	// Create a new instance.
	status := churp.Status{
		Identity:        req.Identity,
		GroupID:         req.GroupID,
		Threshold:       req.Threshold,
		Round:           0,
		NextHandoff:     nextHandoff,
		HandoffInterval: req.HandoffInterval,
		Policy:          req.Policy,
		Committee:       nil,
		Applications:    nil,
		Checksum:        nil,
	}

	if err := state.SetStatus(ctx, &status); err != nil {
		ctx.Logger().Error("keymanager: churp: failed to set status",
			"err", err,
		)
		return fmt.Errorf("keymanager: churp: failed to set status: %w", err)
	}

	ctx.EmitEvent(tmapi.NewEventBuilder(ext.appName).TypedAttribute(&churp.CreateEvent{
		Status: &status,
	}))

	return nil
}

func (ext *churpExt) update(ctx *tmapi.Context, req *churp.UpdateRequest) error {
	// Prepare state.
	state := churpState.NewMutableState(ctx.State())

	// Ensure that the runtime exists and is a key manager.
	kmRt, err := common.KeyManagerRuntime(ctx, req.RuntimeID)
	if err != nil {
		return err
	}

	// Ensure that the tx signer is the key manager owner.
	if !kmRt.EntityID.Equal(ctx.TxSigner()) {
		return fmt.Errorf("keymanager: churp: invalid signer")
	}

	// Get the existing status.
	status, err := state.Status(ctx, req.RuntimeID, req.ID)
	if err != nil {
		return fmt.Errorf("keymanager: churp: non-existing ID: %d", req.ID)
	}

	// Verify data.
	if err = req.ValidateBasic(); err != nil {
		return fmt.Errorf("keymanager: churp: invalid config: %w", err)
	}

	// Handle handoff interval change.
	if req.HandoffInterval != nil {
		switch {
		case *req.HandoffInterval == 0:
			// Cancel and disable handoffs.
			status.NextHandoff = churp.HandoffsDisabled
			status.Applications = nil
			status.Checksum = nil
		case status.HandoffInterval == 0:
			// Schedule the next handoff.
			status.NextHandoff, err = ext.computeNextHandoff(ctx)
			if err != nil {
				return err
			}
		default:
			// Preserve the scheduled handoff and transition
			// to the new interval thereafter.
		}
		status.HandoffInterval = *req.HandoffInterval
	}

	// Handle policy change.
	if req.Policy != nil {
		if err = req.Policy.SanityCheck(&status.Policy.Policy); err != nil {
			return fmt.Errorf("keymanager: churp: invalid config: %w", err)
		}
		status.Policy = *req.Policy
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this operation.
	kmParams, err := state.ConsensusParameters(ctx)
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, churp.GasOpUpdate, kmParams.GasCosts); err != nil {
		return err
	}

	// Return early if simulating since this is just estimating gas.
	if ctx.IsSimulation() {
		return nil
	}

	if err := state.SetStatus(ctx, status); err != nil {
		ctx.Logger().Error("keymanager: churp: failed to set status",
			"err", err,
		)
		return fmt.Errorf("keymanager: churp: failed to set status: %w", err)
	}

	ctx.EmitEvent(tmapi.NewEventBuilder(ext.appName).TypedAttribute(&churp.UpdateEvent{
		Status: status,
	}))

	return nil
}

func (ext *churpExt) computeNextHandoff(ctx *tmapi.Context) (beacon.EpochTime, error) {
	// The next handoff will start at the beginning of the next epoch,
	// meaning that nodes need to send their applications until the end
	// of the current epoch.
	epoch, err := ext.state.GetCurrentEpoch(ctx)
	if err != nil {
		return 0, err
	}
	return epoch + 1, nil
}
