package churp

import (
	"fmt"
	"sort"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	kmCommon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/common"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (ext *churpExt) create(ctx *tmapi.Context, req *churp.CreateRequest) error {
	// Prepare state.
	state := churpState.NewMutableState(ctx.State())

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

	// Ensure that the runtime exists and is a key manager.
	kmRt, err := kmCommon.KeyManagerRuntime(ctx, req.RuntimeID)
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

	// Return early if this is a CheckTx context.
	if ctx.IsCheckOnly() {
		return nil
	}

	// Start a new transaction and rollback in case we fail.
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	// Add stake claim to the key manager owner.
	if err = addStakeClaim(ctx, kmRt.EntityID, req.RuntimeID, req.ID); err != nil {
		return err
	}

	// Create a new instance.
	status := churp.Status{
		Identity:        req.Identity,
		SuiteID:         req.SuiteID,
		Threshold:       req.Threshold,
		ExtraShares:     req.ExtraShares,
		HandoffInterval: req.HandoffInterval,
		Policy:          req.Policy,
		Handoff:         0,
		Checksum:        nil,
		Committee:       nil,
		NextHandoff:     nextHandoff,
		NextChecksum:    nil,
		Applications:    nil,
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

	ctx.Commit()

	return nil
}

func (ext *churpExt) update(ctx *tmapi.Context, req *churp.UpdateRequest) error {
	// Prepare state.
	state := churpState.NewMutableState(ctx.State())

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

	// Ensure that the runtime exists and is a key manager.
	kmRt, err := kmCommon.KeyManagerRuntime(ctx, req.RuntimeID)
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

	// Handle extra shares change.
	if req.ExtraShares != nil {
		status.ExtraShares = *req.ExtraShares
	}

	// Handle handoff interval change.
	if req.HandoffInterval != nil {
		switch {
		case *req.HandoffInterval == 0:
			// Cancel and disable handoffs.
			status.NextHandoff = churp.HandoffsDisabled
			status.NextChecksum = nil
			status.Applications = nil
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

	// Return early if this is a CheckTx context.
	if ctx.IsCheckOnly() {
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

func (ext *churpExt) apply(ctx *tmapi.Context, req *churp.SignedApplicationRequest) error {
	// Prepare state.
	state := churpState.NewMutableState(ctx.State())

	// Charge gas for this operation.
	kmParams, err := state.ConsensusParameters(ctx)
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, churp.GasOpApply, kmParams.GasCosts); err != nil {
		return err
	}

	// Return early if simulating since this is just estimating gas.
	if ctx.IsSimulation() {
		return nil
	}

	// Ensure that the runtime exists and is a key manager.
	kmRt, err := kmCommon.KeyManagerRuntime(ctx, req.Application.RuntimeID)
	if err != nil {
		return err
	}

	// Get the existing status.
	status, err := state.Status(ctx, req.Application.RuntimeID, req.Application.ID)
	if err != nil {
		return fmt.Errorf("keymanager: churp: non-existing ID: %d", req.Application.ID)
	}

	// Check if handoffs are enabled.
	if status.HandoffsDisabled() {
		return fmt.Errorf("keymanager: churp: handoffs disabled")
	}

	// Allow applications one epoch before the next handoff.
	now, err := ext.state.GetCurrentEpoch(ctx)
	if err != nil {
		return err
	}
	if status.NextHandoff != now+1 {
		return fmt.Errorf("keymanager: churp: submissions closed")
	}
	if status.NextHandoff != req.Application.Epoch {
		return fmt.Errorf("keymanager: churp: invalid handoff: got %d, expected %d", req.Application.Epoch, status.NextHandoff)
	}

	// Allow only one application per round, to ensure the node's
	// verification matrix (commitment) doesn't change.
	nodeID := ctx.TxSigner()
	if _, ok := status.Applications[nodeID]; ok {
		return fmt.Errorf("keymanager: churp: application already submitted")
	}

	// Verify RAK signature.
	rak, err := runtimeAttestationKey(ctx, nodeID, now, kmRt)
	if err != nil {
		return err
	}
	if err = req.VerifyRAK(rak); err != nil {
		return fmt.Errorf("keymanager: churp: invalid signature: %w", err)
	}

	// Return early if this is a CheckTx context.
	if ctx.IsCheckOnly() {
		return nil
	}

	// Ok, as far as we can tell the application is valid, apply it.
	if status.Applications == nil {
		status.Applications = make(map[signature.PublicKey]churp.Application)
	}
	status.Applications[nodeID] = churp.Application{
		Checksum:      req.Application.Checksum,
		Reconstructed: false,
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

func (ext *churpExt) confirm(ctx *tmapi.Context, req *churp.SignedConfirmationRequest) error {
	// Prepare state.
	state := churpState.NewMutableState(ctx.State())

	// Charge gas for this operation.
	kmParams, err := state.ConsensusParameters(ctx)
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, churp.GasOpConfirm, kmParams.GasCosts); err != nil {
		return err
	}

	// Return early if simulating since this is just estimating gas.
	if ctx.IsSimulation() {
		return nil
	}

	// Ensure that the runtime exists and is a key manager.
	kmRt, err := kmCommon.KeyManagerRuntime(ctx, req.Confirmation.RuntimeID)
	if err != nil {
		return err
	}

	// Get the existing status.
	status, err := state.Status(ctx, req.Confirmation.RuntimeID, req.Confirmation.ID)
	if err != nil {
		return fmt.Errorf("keymanager: churp: non-existing ID: %d", req.Confirmation.ID)
	}

	// Check if handoffs are enabled.
	if status.HandoffsDisabled() {
		return fmt.Errorf("keymanager: churp: handoffs disabled")
	}

	// Allow confirmations only during the next handoff.
	now, err := ext.state.GetCurrentEpoch(ctx)
	if err != nil {
		return err
	}
	if status.NextHandoff != now {
		return fmt.Errorf("keymanager: churp: confirmations closed")
	}
	if status.NextHandoff != req.Confirmation.Epoch {
		return fmt.Errorf("keymanager: churp: invalid handoff: got %d, expected %d", req.Confirmation.Epoch, status.NextHandoff)
	}

	// Check that application exists.
	nodeID := ctx.TxSigner()
	app, ok := status.Applications[nodeID]
	if !ok {
		return fmt.Errorf("keymanager: churp: application not found")
	}

	// Allow only one confirmation per handoff.
	if app.Reconstructed {
		return fmt.Errorf("keymanager: churp: confirmation already submitted")
	}

	// Verify checksum.
	switch status.NextChecksum {
	case nil:
		// The first node to confirm is the source of truth.
		status.NextChecksum = &req.Confirmation.Checksum
	default:
		// Other nodes need to confirm with the same checksum.
		if !req.Confirmation.Checksum.Equal(status.NextChecksum) {
			return fmt.Errorf("keymanager: churp: checksum mismatch: got %s, expected %s", req.Confirmation.Checksum, status.NextChecksum)
		}
	}

	// Verify RAK signature.
	rak, err := runtimeAttestationKey(ctx, nodeID, now, kmRt)
	if err != nil {
		return err
	}
	if err = req.VerifyRAK(rak); err != nil {
		return fmt.Errorf("keymanager: churp: invalid signature: %w", err)
	}

	// Return early if this is a CheckTx context.
	if ctx.IsCheckOnly() {
		return nil
	}

	// Update application.
	status.Applications[nodeID] = churp.Application{
		Checksum:      app.Checksum,
		Reconstructed: true,
	}

	// Try to finalize the handoff.
	_ = tryFinalizeHandoff(status, false)

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

func addStakeClaim(ctx *tmapi.Context, entityID signature.PublicKey, runtimeID common.Namespace, churpID uint8) error {
	stakeState := stakingState.NewMutableState(ctx.State())

	regParams, err := stakeState.ConsensusParameters(ctx)
	if err != nil {
		return err
	}
	if regParams.DebugBypassStake {
		return nil
	}

	entityAddr := staking.NewAddress(entityID)
	if err != nil {
		return err
	}

	claim := churp.StakeClaim(runtimeID, churpID)
	thresholds := churp.StakeThresholds()

	if err = stakingState.AddStakeClaim(ctx, entityAddr, claim, thresholds); err != nil {
		ctx.Logger().Debug("keymanager: churp: insufficient stake",
			"err", err,
			"entity", entityID,
			"runtime", runtimeID,
			"churp", churpID,
			"account", entityAddr,
		)
		return fmt.Errorf("keymanager: churp: insufficient stake: %w", err)
	}

	return nil
}

func runtimeAttestationKey(ctx *tmapi.Context, nodeID signature.PublicKey, now beacon.EpochTime, kmRt *api.Runtime) (*signature.PublicKey, error) {
	regState := registryState.NewMutableState(ctx.State())

	// Verify the node.
	n, err := regState.Node(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if n.IsExpired(uint64(now)) {
		return nil, fmt.Errorf("keymanager: churp: node registration expired")
	}
	if !n.HasRoles(node.RoleKeyManager) {
		return nil, fmt.Errorf("keymanager: churp: node not key manager")
	}

	// Fetch RAK.
	nodeRt, err := kmCommon.NodeRuntime(n, kmRt.ID)
	if err != nil {
		return nil, err
	}
	rak, err := kmCommon.RuntimeAttestationKey(nodeRt, kmRt)
	if err != nil {
		return nil, fmt.Errorf("keymanager: churp: failed to fetch node's rak: %w", err)
	}

	return rak, nil
}

func tryFinalizeHandoff(status *churp.Status, epochChange bool) bool {
	// Prepare the new committee.
	committee := make([]signature.PublicKey, 0, len(status.Applications))
	for node, app := range status.Applications {
		if app.Reconstructed {
			committee = append(committee, node)
		}
	}

	// Verify the committee size if the number of extra shares has changed.
	if len(committee) < status.MinCommitteeSize() {
		return false
	}

	// During the handoff epoch, all applicants must send confirmation.
	if !epochChange && len(committee) != len(status.Applications) {
		return false
	}

	// Sort the committee to ensure a deterministic order.
	sort.SliceStable(committee, func(i, j int) bool {
		for k := 0; k < signature.PublicKeySize; k++ {
			if committee[i][k] != committee[j][k] {
				return committee[i][k] < committee[j][k]
			}
		}
		return false
	})

	// Update fields.
	status.Handoff = status.NextHandoff
	status.Checksum = status.NextChecksum
	status.Committee = committee
	status.NextHandoff = status.Handoff + status.HandoffInterval
	status.NextChecksum = nil
	status.Applications = nil

	// Give nodes an extra epoch for application submission.
	if epochChange && status.HandoffInterval == 1 {
		status.NextHandoff++
	}

	return true
}

func resetHandoff(status *churp.Status, nextHandoff beacon.EpochTime) {
	status.NextHandoff = nextHandoff
	status.NextChecksum = nil
	status.Applications = nil
}
