package registry

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func (app *registryApplication) registerEntity(
	ctx *abci.Context,
	state *registryState.MutableState,
	sigEnt *entity.SignedEntity,
) error {
	ent, err := registry.VerifyRegisterEntityArgs(ctx.Logger(), sigEnt, ctx.IsInitChain())
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
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

	if !params.DebugBypassStake {
		if err = stakingState.EnsureSufficientStake(ctx, ent.ID, []staking.ThresholdKind{staking.KindEntity}); err != nil {
			ctx.Logger().Error("RegisterEntity: Insufficent stake",
				"err", err,
				"id", ent.ID,
			)
			return err
		}
	}

	// Make sure the signer of the transaction matches the signer of the entity.
	// NOTE: If this is invoked during InitChain then there is no actual transaction
	//       and thus no transaction signer so we must skip this check.
	if !ctx.IsInitChain() && !sigEnt.Signature.PublicKey.Equal(ctx.TxSigner()) {
		return registry.ErrIncorrectTxSigner
	}

	state.SetEntity(ent, sigEnt)

	ctx.Logger().Debug("RegisterEntity: registered",
		"entity", ent,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEntityRegistered, cbor.Marshal(ent)))

	return nil
}

func (app *registryApplication) deregisterEntity(ctx *abci.Context, state *registryState.MutableState) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
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
	hasNodes, err := state.HasEntityNodes(id)
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
	hasRuntimes, err := state.HasEntityRuntimes(id)
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

	removedEntity, err := state.RemoveEntity(id)
	if err != nil {
		return err
	}

	ctx.Logger().Debug("DeregisterEntity: complete",
		"entity_id", id,
	)

	tagV := &EntityDeregistration{
		Entity: *removedEntity,
	}
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEntityDeregistered, cbor.Marshal(tagV)))

	return nil
}

func (app *registryApplication) registerNode( // nolint: gocyclo
	ctx *abci.Context,
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
	untrustedEntity, err := state.Entity(untrustedNode.EntityID)
	if err != nil {
		ctx.Logger().Error("RegisterNode: failed to query owning entity",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}

	params, err := state.ConsensusParameters()
	if err != nil {
		ctx.Logger().Error("RegisterNode: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}

	epoch, err := app.state.GetEpoch(ctx.Ctx(), ctx.BlockHeight()+1)
	if err != nil {
		ctx.Logger().Error("RegisterNode: failed to get epoch",
			"err", err,
		)
		return err
	}

	newNode, paidRuntimes, err := registry.VerifyRegisterNodeArgs(
		params,
		ctx.Logger(),
		sigNode,
		untrustedEntity,
		ctx.Now(),
		ctx.IsInitChain(),
		epoch,
		state,
		state,
	)
	if err != nil {
		return err
	}

	// Charge gas for node registration if signed by entity. For node-signed
	// registrations, the gas charges are pre-paid by the entity.
	isEntitySigned := sigNode.MultiSigned.IsSignedBy(newNode.EntityID)
	if isEntitySigned {
		if err = ctx.Gas().UseGas(1, registry.GasOpRegisterNode, params.GasCosts); err != nil {
			return err
		}
	}

	// Make sure the signer of the transaction is the node identity key
	// or the entity (iff the registration is entity signed).
	// NOTE: If this is invoked during InitChain then there is no actual transaction
	//       and thus no transaction signer so we must skip this check.
	if !ctx.IsInitChain() {
		expectedTxSigner := newNode.ID
		if isEntitySigned {
			expectedTxSigner = newNode.EntityID
		}
		if !ctx.TxSigner().Equal(expectedTxSigner) {
			return registry.ErrIncorrectTxSigner
		}
	}

	// Check runtime's whitelist.
	for _, rt := range paidRuntimes {
		if rt.AdmissionPolicy.EntityWhitelist != nil && !rt.AdmissionPolicy.EntityWhitelist.Entities[newNode.EntityID] {
			ctx.Logger().Error("RegisterNode: node's entity not in a runtime's whitelist",
				"entity", newNode.EntityID,
				"runtime", rt.ID,
			)
			return registry.ErrForbidden
		}
	}

	// Re-check that the entity has at sufficient stake to still be an entity.
	var (
		stakeCache     *stakingState.StakeCache
		numEntityNodes int
	)
	if !params.DebugBypassStake {
		if stakeCache, err = stakingState.NewStakeCache(ctx); err != nil {
			ctx.Logger().Error("RegisterNode: failed to instantiate stake cache",
				"err", err,
			)
			return err
		}

		if err = stakeCache.EnsureSufficientStake(newNode.EntityID, []staking.ThresholdKind{staking.KindEntity}); err != nil {
			ctx.Logger().Error("RegisterNode: insufficient stake, entity no longer valid",
				"err", err,
				"id", newNode.EntityID,
			)
			return err
		}

		if numEntityNodes, err = state.NumEntityNodes(newNode.EntityID); err != nil {
			ctx.Logger().Error("RegisterNode: failed to query existing nodes for entity",
				"err", err,
				"entity", newNode.EntityID,
			)
			return err
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
	existingNode, err := state.Node(newNode.ID)
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

	// Create a new state checkpoint and rollback in case we fail.
	var ok bool
	sc := ctx.NewStateCheckpoint()
	defer func() {
		if !ok {
			sc.Rollback()
		}
		sc.Close()
	}()

	if isNewNode || isExpiredNode {
		// Check that the entity has enough stake for this node registration.
		if !params.DebugBypassStake {
			if err = stakeCache.EnsureNodeRegistrationStake(newNode.EntityID, numEntityNodes+1); err != nil {
				ctx.Logger().Error("RegisterNode: insufficient stake for new node",
					"err", err,
					"entity", newNode.EntityID,
				)
				return err
			}
		}

		// Node doesn't exist (or is expired). Create node.
		if err = state.SetNode(newNode, sigNode); err != nil {
			ctx.Logger().Error("RegisterNode: failed to create node",
				"err", err,
				"node", newNode,
				"entity", newNode.EntityID,
			)
			return registry.ErrBadEntityForNode
		}

		var status *registry.NodeStatus
		if existingNode != nil {
			// Node exists but is expired, fetch existing status.
			if status, err = state.NodeStatus(newNode.ID); err != nil {
				ctx.Logger().Error("RegisterNode: failed to get node status",
					"err", err,
				)
				return registry.ErrInvalidArgument
			}

			// Reset expiration processed flag as the node is live again.
			status.ExpirationProcessed = false
		} else {
			// Node doesn't exist, create empty status.
			status = &registry.NodeStatus{}
		}

		if err = state.SetNodeStatus(newNode.ID, status); err != nil {
			ctx.Logger().Error("RegisterNode: failed to set node status",
				"err", err,
			)
			return registry.ErrInvalidArgument
		}
	} else {
		// Check that the entity has enough stake for the existing node
		// registrations.
		if !params.DebugBypassStake {
			if err = stakeCache.EnsureNodeRegistrationStake(newNode.EntityID, numEntityNodes); err != nil {
				ctx.Logger().Error("RegisterNode: insufficient stake for existing nodes",
					"err", err,
					"entity", newNode.EntityID,
				)
				return err
			}
		}

		// The node already exists, validate and update the node's entry.
		if err = registry.VerifyNodeUpdate(ctx.Logger(), existingNode, newNode); err != nil {
			ctx.Logger().Error("RegisterNode: failed to verify node update",
				"err", err,
				"new_node", newNode,
				"existing_node", existingNode,
				"entity", newNode.EntityID,
			)
			return err
		}
		if err = state.SetNode(newNode, sigNode); err != nil {
			ctx.Logger().Error("RegisterNode: failed to update node",
				"err", err,
				"node", newNode,
				"entity", newNode.EntityID,
			)
			return registry.ErrBadEntityForNode
		}
	}

	// If a runtime was previously suspended and this node now paid maintenance
	// fees for it, resume the runtime.
	for _, rt := range paidRuntimes {
		err := state.ResumeRuntime(rt.ID)
		switch err {
		case nil:
			ctx.Logger().Debug("RegisterNode: resumed runtime",
				"runtime_id", rt.ID,
			)

			ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyRuntimeRegistered, cbor.Marshal(rt)))
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

	ok = true

	ctx.Logger().Debug("RegisterNode: registered",
		"node", newNode,
		"roles", newNode.Roles,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyNodeRegistered, cbor.Marshal(newNode)))

	return nil
}

func (app *registryApplication) unfreezeNode(
	ctx *abci.Context,
	state *registryState.MutableState,
	unfreeze *registry.UnfreezeNode,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
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
	node, err := state.Node(unfreeze.NodeID)
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
	status, err := state.NodeStatus(unfreeze.NodeID)
	if err != nil {
		ctx.Logger().Error("UnfreezeNode: failed to fetch node status",
			"err", err,
			"node_id", unfreeze.NodeID,
			"entity_id", node.EntityID,
		)
		return err
	}

	// Ensure if we can actually unfreeze.
	epoch, err := app.state.GetEpoch(ctx.Ctx(), ctx.BlockHeight()+1)
	if err != nil {
		return err
	}
	if status.FreezeEndTime > epoch {
		return registry.ErrNodeCannotBeUnfrozen
	}

	// Reset frozen status.
	status.Unfreeze()
	if err = state.SetNodeStatus(node.ID, status); err != nil {
		return err
	}

	ctx.Logger().Debug("UnfreezeNode: unfrozen",
		"node_id", node.ID,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyNodeUnfrozen, cbor.Marshal(node.ID)))

	return nil
}

func (app *registryApplication) registerRuntime(
	ctx *abci.Context,
	state *registryState.MutableState,
	sigRt *registry.SignedRuntime,
) error {
	params, err := state.ConsensusParameters()
	if err != nil {
		ctx.Logger().Error("RegisterRuntime: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}

	rt, err := registry.VerifyRegisterRuntimeArgs(params, ctx.Logger(), sigRt, ctx.IsInitChain())
	if err != nil {
		return err
	}

	// Runtime with genesis stateroot only allowed in genesis.
	if !ctx.IsInitChain() && !rt.Genesis.StateRoot.IsEmpty() {
		ctx.Logger().Error("RegisterRuntime: runtime genesis state root not empty")
		// TODO: Verify storage receipt for the state root, reject such registrations for now. See oasis-core#1686.
		return registry.ErrInvalidArgument
	}

	if rt.Kind == registry.KindCompute {
		if err = registry.VerifyRegisterComputeRuntimeArgs(ctx.Logger(), rt, state); err != nil {
			return err
		}
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	if err = ctx.Gas().UseGas(1, registry.GasOpRegisterRuntime, params.GasCosts); err != nil {
		return err
	}

	// Make sure the signer of the transaction matches the signer of the runtime.
	// NOTE: If this is invoked during InitChain then there is no actual transaction
	//       and thus no transaction signer so we must skip this check.
	if !ctx.IsInitChain() && !sigRt.Signature.PublicKey.Equal(ctx.TxSigner()) {
		return registry.ErrIncorrectTxSigner
	}

	// If TEE is required, check if runtime provided at least one enclave ID.
	if rt.TEEHardware != node.TEEHardwareInvalid {
		switch rt.TEEHardware {
		case node.TEEHardwareIntelSGX:
			var vi registry.VersionInfoIntelSGX
			if err = cbor.Unmarshal(rt.Version.TEE, &vi); err != nil {
				return err
			}
			if len(vi.Enclaves) == 0 {
				return registry.ErrNoEnclaveForRuntime
			}
		}
	}

	// Make sure the runtime doesn't exist yet.
	var suspended bool
	existingRt, err := state.Runtime(rt.ID)
	switch err {
	case nil:
	case registry.ErrNoSuchRuntime:
		// Make sure the runtime isn't suspended.
		existingRt, err = state.SuspendedRuntime(rt.ID)
		switch err {
		case nil:
			suspended = true
		case registry.ErrNoSuchRuntime:
		default:
			return fmt.Errorf("failed to fetch suspended runtime: %w", err)
		}
	default:
		return fmt.Errorf("failed to fetch runtime: %w", err)
	}
	// If there is an existing runtime, verify update.
	if existingRt != nil {
		err = registry.VerifyRuntimeUpdate(ctx.Logger(), existingRt, rt)
		if err != nil {
			return err
		}
	}

	if err = state.SetRuntime(rt, sigRt, suspended); err != nil {
		ctx.Logger().Error("RegisterRuntime: failed to create runtime",
			"err", err,
			"runtime", rt,
			"entity", rt.EntityID,
		)
		return registry.ErrBadEntityForRuntime
	}

	if !suspended {
		ctx.Logger().Debug("RegisterRuntime: registered",
			"runtime", rt,
		)

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyRuntimeRegistered, cbor.Marshal(rt)))
	}

	return nil
}
