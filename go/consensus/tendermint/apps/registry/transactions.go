package registry

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	registryApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *registryApplication) registerEntity(
	ctx *api.Context,
	state *registryState.MutableState,
	sigEnt *entity.SignedEntity,
) error {
	ent, err := registry.VerifyRegisterEntityArgs(ctx.Logger(), sigEnt, ctx.IsInitChain(), false)
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("RegisterEntity: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if err = ctx.Gas().UseGas(1, registry.GasOpRegisterEntity, params.GasCosts); err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(len(ent.Nodes), registry.GasOpRegisterNode, params.GasCosts); err != nil {
		return err
	}

	// Make sure the signer of the transaction matches the signer of the entity.
	// NOTE: If this is invoked during InitChain then there is no actual transaction
	//       and thus no transaction signer so we must skip this check.
	if !ctx.IsInitChain() && !sigEnt.Signature.PublicKey.Equal(ctx.TxSigner()) {
		return registry.ErrIncorrectTxSigner
	}

	if !params.DebugBypassStake {
		acctAddr := staking.NewAddress(ent.ID)
		if err = stakingState.AddStakeClaim(
			ctx,
			acctAddr,
			registry.StakeClaimRegisterEntity,
			staking.GlobalStakeThresholds(staking.KindEntity),
		); err != nil {
			ctx.Logger().Error("RegisterEntity: Insufficient stake",
				"err", err,
				"entity", ent.ID,
				"account", acctAddr,
			)
			return err
		}
	}

	if err = state.SetEntity(ctx, ent, sigEnt); err != nil {
		return fmt.Errorf("failed to set entity: %w", err)
	}

	ctx.Logger().Debug("RegisterEntity: registered",
		"entity", ent,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&registry.EntityEvent{Entity: ent, IsRegistration: true}))

	return nil
}

func (app *registryApplication) deregisterEntity(ctx *api.Context, state *registryState.MutableState) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("DeregisterEntity: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if err = ctx.Gas().UseGas(1, registry.GasOpDeregisterEntity, params.GasCosts); err != nil {
		return err
	}

	id := ctx.TxSigner()

	// Prevent entity deregistration if there are any registered nodes.
	hasNodes, err := state.HasEntityNodes(ctx, id)
	if err != nil {
		ctx.Logger().Error("DeregisterEntity: failed to check for nodes",
			"err", err,
		)
		return err
	}
	if hasNodes {
		ctx.Logger().Error("DeregisterEntity: entity still has nodes",
			"entity_id", id,
		)
		return registry.ErrEntityHasNodes
	}
	// Prevent entity deregistration if there are any registered runtimes.
	hasRuntimes, err := state.HasEntityRuntimes(ctx, id)
	if err != nil {
		ctx.Logger().Error("DeregisterEntity: failed to check for runtimes",
			"err", err,
		)
		return err
	}
	if hasRuntimes {
		ctx.Logger().Error("DeregisterEntity: entity still has runtimes",
			"entity_id", id,
		)
		return registry.ErrEntityHasRuntimes
	}

	removedEntity, err := state.RemoveEntity(ctx, id)
	switch err {
	case nil:
	case registry.ErrNoSuchEntity:
		return err
	default:
		return fmt.Errorf("DeregisterEntity: failed to remove entity: %w", err)
	}

	if !params.DebugBypassStake {
		acctAddr := staking.NewAddress(id)
		if err = stakingState.RemoveStakeClaim(ctx, acctAddr, registry.StakeClaimRegisterEntity); err != nil {
			panic(fmt.Errorf("DeregisterEntity: failed to remove stake claim: %w", err))
		}
	}

	ctx.Logger().Debug("DeregisterEntity: complete",
		"entity_id", id,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&registry.EntityEvent{Entity: removedEntity, IsRegistration: false}))

	return nil
}

func (app *registryApplication) registerNode( // nolint: gocyclo
	ctx *api.Context,
	state *registryState.MutableState,
	sigNode *node.MultiSignedNode,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Peek into the to-be-verified node to pull out the owning entity ID.
	var untrustedNode node.Node
	if err := cbor.Unmarshal(sigNode.Blob, &untrustedNode); err != nil {
		ctx.Logger().Error("RegisterNode: failed to extract entity",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}
	untrustedEntity, err := state.Entity(ctx, untrustedNode.EntityID)
	if err != nil {
		ctx.Logger().Error("RegisterNode: failed to query owning entity",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("RegisterNode: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}

	epoch, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		ctx.Logger().Error("RegisterNode: failed to get epoch",
			"err", err,
		)
		return err
	}

	newNode, paidRuntimes, err := registry.VerifyRegisterNodeArgs(
		ctx,
		params,
		ctx.Logger(),
		sigNode,
		untrustedEntity,
		ctx.Now(),
		ctx.IsInitChain(),
		false,
		epoch,
		state,
		state,
	)
	if err != nil {
		return err
	}

	// Make sure the signer of the transaction is the node identity key.
	// NOTE: If this is invoked during InitChain then there is no actual transaction
	//       and thus no transaction signer so we must skip this check.
	if !ctx.IsInitChain() {
		if !ctx.TxSigner().Equal(newNode.ID) {
			return registry.ErrIncorrectTxSigner
		}
	}

	// Check runtime's whitelist.
	for _, rt := range paidRuntimes {
		if rt.AdmissionPolicy.EntityWhitelist == nil {
			continue
		}
		wcfg, entIsWhitelisted := rt.AdmissionPolicy.EntityWhitelist.Entities[newNode.EntityID]
		if !entIsWhitelisted {
			ctx.Logger().Error("RegisterNode: node's entity not in a runtime's whitelist",
				"entity", newNode.EntityID,
				"runtime", rt.ID,
			)
			return registry.ErrForbidden
		}
		if len(wcfg.MaxNodes) == 0 {
			continue
		}

		// Map is present and non-empty, check per-role restrictions
		// on the maximum number of nodes per entity.

		// Iterate over all valid roles (each entry in the map can
		// only have a single role).
		for _, role := range node.Roles() {
			if !newNode.HasRoles(role) {
				// Skip unset roles.
				continue
			}

			maxNodes, exists := wcfg.MaxNodes[role]
			if !exists {
				// No such role found in whitelist.
				ctx.Logger().Error("RegisterNode: runtime's whitelist does not allow nodes with given role",
					"role", role.String(),
					"runtime", rt.ID,
				)
				return registry.ErrForbidden
			}
			if maxNodes == 0 {
				// No nodes of this type are allowed.
				ctx.Logger().Error("RegisterNode: runtime's whitelist does not allow nodes with given role",
					"role", role.String(),
					"runtime", rt.ID,
				)
				return registry.ErrForbidden
			}

			// Count existing nodes owned by entity.
			nodes, grr := state.GetEntityNodes(ctx, newNode.EntityID)
			if grr != nil {
				ctx.Logger().Error("RegisterNode: failed to query entity nodes",
					"err", grr,
					"entity", newNode.EntityID,
				)
				return grr
			}
			var curNodes uint16
			for _, n := range nodes {
				if n.ID.Equal(newNode.ID) || n.IsExpired(uint64(epoch)) || n.GetRuntime(rt.ID) == nil {
					// Skip existing node when re-registering.  Also skip
					// expired nodes and nodes that haven't registered
					// for the same runtime.
					continue
				}

				if n.HasRoles(role) {
					curNodes++
				}

				// The check is inside the for loop, so we can stop as
				// soon as possible once we're over the limit.
				if curNodes+1 > maxNodes {
					// Too many nodes with given role already registered.
					ctx.Logger().Error("RegisterNode: too many nodes with given role already registered for runtime",
						"role", role.String(),
						"runtime", rt.ID,
						"num_registered_nodes", curNodes,
					)
					return registry.ErrForbidden
				}
			}
		}
	}

	// Ensure node is not expired. Even though the expiration in the
	// current epoch is technically not yet expired, we treat it as
	// expired as it doesn't make sense to have a new node that will
	// immediately expire.
	//
	// Yes, this is duplicated.  Blame the sanity checker.
	if !ctx.IsInitChain() && newNode.Expiration <= uint64(epoch) {
		ctx.Logger().Error("RegisterNode: node descriptor is expired",
			"new_node", newNode,
			"epoch", epoch,
		)
		return registry.ErrNodeExpired
	}

	var additionalEpochs uint64
	if newNode.Expiration > uint64(epoch) {
		additionalEpochs = newNode.Expiration - uint64(epoch)
	}

	// Check if node exists.
	existingNode, err := state.Node(ctx, newNode.ID)
	isNewNode := err == registry.ErrNoSuchNode
	isExpiredNode := err == nil && existingNode.IsExpired(uint64(epoch))
	if !isNewNode && err != nil {
		// Something went horribly wrong, and we failed to query the node.
		ctx.Logger().Error("RegisterNode: failed to query node",
			"err", err,
			"new_node", newNode,
			"existing_node", existingNode,
			"entity", newNode.EntityID,
		)
		return registry.ErrInvalidArgument
	}

	// For each runtime the node registers for, require it to pay a maintenance fee for
	// each epoch the node is registered in.
	if !isNewNode && !isExpiredNode {
		// Remaining epochs are credited so the node doesn't end up paying twice.
		// NOTE: This assumes that changing runtimes is not allowed as otherwise we
		//       would need to account this per-runtime.
		remainingEpochs := existingNode.Expiration - uint64(epoch)
		if additionalEpochs > remainingEpochs {
			additionalEpochs = additionalEpochs - remainingEpochs
		} else {
			additionalEpochs = 0
		}
	}
	feeCount := len(paidRuntimes) * int(additionalEpochs)
	if err = ctx.Gas().UseGas(feeCount, registry.GasOpRuntimeEpochMaintenance, params.GasCosts); err != nil {
		return err
	}

	// Start a new transaction and rollback in case we fail.
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	// Check that the entity has enough stake for this node registration.
	var stakeAcc *stakingState.StakeAccumulatorCache
	if !params.DebugBypassStake {
		stakeAcc, err = stakingState.NewStakeAccumulatorCache(ctx)
		if err != nil {
			return fmt.Errorf("failed to create stake accumulator cache: %w", err)
		}

		claim := registry.StakeClaimForNode(newNode.ID)
		thresholds := registry.StakeThresholdsForNode(newNode, paidRuntimes)
		acctAddr := staking.NewAddress(newNode.EntityID)

		if err = stakeAcc.AddStakeClaim(acctAddr, claim, thresholds); err != nil {
			ctx.Logger().Error("RegisterNode: insufficient stake for new node",
				"err", err,
				"entity", newNode.EntityID,
				"account", acctAddr,
			)
			return err
		}
		if err = stakeAcc.Commit(); err != nil {
			return fmt.Errorf("failed to commit stake accumulator updates: %w", err)
		}
	}

	// If the node already exists make sure to verify the node update.
	if existingNode != nil {
		if err = registry.VerifyNodeUpdate(ctx.Logger(), existingNode, newNode, epoch); err != nil {
			ctx.Logger().Error("RegisterNode: failed to verify node update",
				"err", err,
				"new_node", newNode,
				"existing_node", existingNode,
				"entity", newNode.EntityID,
			)
			return err
		}
	}
	if err = state.SetNode(ctx, existingNode, newNode, sigNode); err != nil {
		ctx.Logger().Error("RegisterNode: failed to create/update node",
			"err", err,
			"node", newNode,
			"entity", newNode.EntityID,
			"is_creation", existingNode == nil,
		)
		return fmt.Errorf("failed to set node: %w", err)
	}

	// Query the current node status if it exists.
	var status *registry.NodeStatus
	if existingNode != nil {
		if status, err = state.NodeStatus(ctx, newNode.ID); err != nil {
			ctx.Logger().Error("RegisterNode: failed to get node status",
				"err", err,
			)
			return registry.ErrInvalidArgument
		}
	}

	// Initialize/update the node status depending on what has changed.
	var statusDirty bool
	if isNewNode || isExpiredNode {
		// Node doesn't exist (or is expired).
		statusDirty = true
		if status != nil {
			// Reset expiration processed flag as the node is live again.
			status.ExpirationProcessed = false
		} else {
			// Node doesn't exist, create empty status.
			status = &registry.NodeStatus{}
		}

		// In either case, the node isn't immediately eligible to serve
		// on a non-validator committee.
		status.ElectionEligibleAfter = beacon.EpochInvalid

	} else {
		// Node exists, and the registration is just getting renewed.
		var beaconParams *beacon.ConsensusParameters
		beaconState := beaconState.NewMutableState(ctx.State())
		if beaconParams, err = beaconState.ConsensusParameters(ctx); err != nil {
			return fmt.Errorf("tendermint/registry: couldn't get beacon parameters: %w", err)
		}
		if beaconParams.Backend == beacon.BackendVRF {
			// If the VRF backend is active, and the node's VRF key has
			// changed, reset election eligibility.
			vrfChanged := func() bool {
				if existingNode.VRF == nil || newNode.VRF == nil {
					return false
				}
				if existingNode.VRF == nil && newNode.VRF != nil {
					return true
				}
				if existingNode.VRF != nil && newNode.VRF == nil {
					return true
				}
				return !existingNode.VRF.ID.Equal(newNode.VRF.ID)
			}()

			if statusDirty = vrfChanged; statusDirty {
				status.ElectionEligibleAfter = beacon.EpochInvalid
			}
		}
	}
	if statusDirty {
		if err = state.SetNodeStatus(ctx, newNode.ID, status); err != nil {
			ctx.Logger().Error("RegisterNode: failed to set node status",
				"err", err,
			)
			return fmt.Errorf("failed to set node status: %w", err)
		}
	}

	// If a runtime was previously suspended and this node now paid maintenance
	// fees for it, resume the runtime.
	for _, rt := range paidRuntimes {
		// Only resume a runtime if the entity has enough stake to avoid having the runtime be
		// suspended again on the next epoch transition.
		if !params.DebugBypassStake && rt.GovernanceModel != registry.GovernanceConsensus {
			acctAddr := rt.StakingAddress()
			if acctAddr == nil {
				// This should never happen.
				ctx.Logger().Error("unknown runtime governance model",
					"rt_id", rt.ID,
					"gov_model", rt.GovernanceModel,
				)
				return fmt.Errorf("unknown runtime governance model on runtime %s: %s", rt.ID, rt.GovernanceModel)
			}

			if err = stakeAcc.CheckStakeClaims(*acctAddr); err != nil {
				continue
			}
		}

		err := state.ResumeRuntime(ctx, rt.ID)
		switch err {
		case nil:
			ctx.Logger().Debug("RegisterNode: resumed runtime",
				"runtime_id", rt.ID,
			)

			// Notify other interested applications about the resumed runtime.
			if _, err = app.md.Publish(ctx, registryApi.MessageRuntimeResumed, rt); err != nil {
				ctx.Logger().Error("RegisterNode: failed to dispatch runtime resumption message",
					"err", err,
				)
				return err
			}

			ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&registry.RuntimeEvent{Runtime: rt}))
		case registry.ErrNoSuchRuntime:
			// Runtime was not suspended.
		default:
			ctx.Logger().Error("RegisterNode: failed to resume suspended runtime",
				"err", err,
				"runtime_id", rt.ID,
			)
			return fmt.Errorf("failed to resume suspended runtime %s: %w", rt.ID, err)
		}
	}

	ctx.Logger().Debug("RegisterNode: registered",
		"node", newNode,
		"roles", newNode.Roles,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&registry.NodeEvent{Node: newNode, IsRegistration: true}))

	ctx.Commit()

	return nil
}

func (app *registryApplication) unfreezeNode(
	ctx *api.Context,
	state *registryState.MutableState,
	unfreeze *registry.UnfreezeNode,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("UnfreezeNode: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if err = ctx.Gas().UseGas(1, registry.GasOpUnfreezeNode, params.GasCosts); err != nil {
		return err
	}

	// Fetch node descriptor.
	node, err := state.Node(ctx, unfreeze.NodeID)
	if err != nil {
		ctx.Logger().Error("UnfreezeNode: failed to fetch node",
			"err", err,
			"node_id", unfreeze.NodeID,
		)
		return err
	}
	// Make sure that the unfreeze request was signed by the owning entity.
	if !ctx.TxSigner().Equal(node.EntityID) {
		return registry.ErrBadEntityForNode
	}

	// Fetch node status.
	status, err := state.NodeStatus(ctx, unfreeze.NodeID)
	if err != nil {
		ctx.Logger().Error("UnfreezeNode: failed to fetch node status",
			"err", err,
			"node_id", unfreeze.NodeID,
			"entity_id", node.EntityID,
		)
		return err
	}

	// Ensure if we can actually unfreeze.
	epoch, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		return err
	}
	if status.FreezeEndTime > epoch {
		return registry.ErrNodeCannotBeUnfrozen
	}

	// Reset frozen status.
	status.Unfreeze()
	if err = state.SetNodeStatus(ctx, node.ID, status); err != nil {
		return fmt.Errorf("failed to set node status: %w", err)
	}

	ctx.Logger().Debug("UnfreezeNode: unfrozen",
		"node_id", node.ID,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&registry.NodeUnfrozenEvent{NodeID: node.ID}))

	return nil
}

func (app *registryApplication) registerRuntime( // nolint: gocyclo
	ctx *api.Context,
	state *registryState.MutableState,
	rt *registry.Runtime,
) (*registry.Runtime, error) {
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("RegisterRuntime: failed to fetch consensus parameters",
			"err", err,
		)
		return nil, err
	}

	if params.DisableRuntimeRegistration {
		return nil, registry.ErrForbidden
	}

	if err = registry.VerifyRuntime(params, ctx.Logger(), rt, ctx.IsInitChain(), false); err != nil {
		return nil, err
	}

	if rt.Kind == registry.KindKeyManager && params.DisableKeyManagerRuntimeRegistration {
		return nil, registry.ErrForbidden
	}

	if rt.Kind == registry.KindCompute {
		if err = registry.VerifyRegisterComputeRuntimeArgs(ctx, ctx.Logger(), rt, state); err != nil {
			return nil, err
		}
	}

	if ctx.IsCheckOnly() {
		return nil, nil
	}

	// Charge gas for this transaction.
	if err = ctx.Gas().UseGas(1, registry.GasOpRegisterRuntime, params.GasCosts); err != nil {
		return nil, err
	}

	// Make sure the runtime doesn't exist yet.
	var suspended bool
	existingRt, err := state.Runtime(ctx, rt.ID)
	switch err {
	case nil:
	case registry.ErrNoSuchRuntime:
		// Make sure the runtime isn't suspended.
		existingRt, err = state.SuspendedRuntime(ctx, rt.ID)
		switch err {
		case nil:
			suspended = true
		case registry.ErrNoSuchRuntime:
		default:
			return nil, fmt.Errorf("failed to fetch suspended runtime: %w", err)
		}
	default:
		return nil, fmt.Errorf("failed to fetch runtime: %w", err)
	}
	// If there is an existing runtime, verify update.
	if existingRt != nil {
		err = registry.VerifyRuntimeUpdate(ctx.Logger(), existingRt, rt)
		if err != nil {
			return nil, err
		}
	}

	if !ctx.IsInitChain() {
		// Make sure the signer of the transaction matches the signer of the
		// entity or runtime that is controlling the runtime.
		// NOTE: If this is invoked during InitChain then there is no actual transaction
		//       and thus no transaction signer so we must skip this check.

		// If we're updating the governance model, we should check the signer
		// based on the existing governance model and not the new one,
		// otherwise it would be impossible to transition from entity to
		// runtime governance, for example.
		var rtToCheck *registry.Runtime
		if existingRt != nil {
			rtToCheck = existingRt
		} else {
			rtToCheck = rt
		}

		expectedAddr := rtToCheck.StakingAddress()
		if expectedAddr == nil {
			ctx.Logger().Error("RegisterRuntime: runtimes with consensus-layer governance can only be registered at genesis")
			return nil, registry.ErrForbidden
		}

		if !ctx.CallerAddress().Equal(*expectedAddr) {
			switch rtToCheck.GovernanceModel {
			case registry.GovernanceEntity:
				ctx.Logger().Error("RegisterRuntime: transaction must be signed by controlling entity")
				return nil, registry.ErrIncorrectTxSigner
			case registry.GovernanceRuntime:
				ctx.Logger().Error("RegisterRuntime: caller must be the runtime itself")
				return nil, registry.ErrForbidden
			default:
				// Basic validation should have caught this, but just in case...
				ctx.Logger().Error("RegisterRuntime: invalid governance model")
				return nil, registry.ErrInvalidArgument
			}
		}
	}

	// Make sure that the entity or runtime has enough stake.
	// Runtimes using the consensus layer governance model do not require stake.
	if !params.DebugBypassStake && rt.GovernanceModel != registry.GovernanceConsensus {
		claim := registry.StakeClaimForRuntime(rt.ID)
		thresholds := registry.StakeThresholdsForRuntime(rt)
		var acctAddr staking.Address
		switch rt.GovernanceModel {
		case registry.GovernanceEntity:
			acctAddr = staking.NewAddress(rt.EntityID)
		case registry.GovernanceRuntime:
			acctAddr = ctx.CallerAddress()
		default:
			// Basic validation should have caught this, but just in case...
			ctx.Logger().Error("RegisterRuntime: invalid governance model")
			return nil, registry.ErrInvalidArgument
		}

		if err = stakingState.AddStakeClaim(ctx, acctAddr, claim, thresholds); err != nil {
			ctx.Logger().Error("RegisterRuntime: insufficient stake",
				"err", err,
				"entity", rt.EntityID,
				"runtime", rt.ID,
				"account", acctAddr,
			)
			return nil, err
		}
	}

	// Notify other interested applications about the new runtime.
	if existingRt == nil {
		if _, err = app.md.Publish(ctx, registryApi.MessageNewRuntimeRegistered, rt); err != nil {
			ctx.Logger().Error("RegisterRuntime: failed to dispatch message",
				"err", err,
			)
			return nil, err
		}
	}

	if _, err = app.md.Publish(ctx, registryApi.MessageRuntimeUpdated, rt); err != nil {
		ctx.Logger().Error("RegisterRuntime: failed to dispatch message",
			"err", err,
		)
		return nil, err
	}

	if err = state.SetRuntime(ctx, rt, suspended); err != nil {
		ctx.Logger().Error("RegisterRuntime: failed to create runtime",
			"err", err,
			"runtime", rt,
			"entity", rt.EntityID,
		)
		return nil, fmt.Errorf("failed to set runtime: %w", err)
	}

	if !suspended {
		ctx.Logger().Debug("RegisterRuntime: registered",
			"runtime", rt,
		)

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&registry.RuntimeEvent{Runtime: rt}))
	}

	return rt, nil
}
