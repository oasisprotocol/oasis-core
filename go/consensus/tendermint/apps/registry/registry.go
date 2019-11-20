// Package registry implements the registry application.
package registry

import (
	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

var _ abci.Application = (*registryApplication)(nil)

type registryApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState
}

func (app *registryApplication) Name() string {
	return AppName
}

func (app *registryApplication) ID() uint8 {
	return AppID
}

func (app *registryApplication) Methods() []transaction.MethodName {
	return registry.Methods
}

func (app *registryApplication) Blessed() bool {
	return false
}

func (app *registryApplication) Dependencies() []string {
	return []string{stakingapp.AppName}
}

func (app *registryApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *registryApplication) OnCleanup() {
}

func (app *registryApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// XXX: With PR#1889 this can be a differnet interval.
	if changed, registryEpoch := app.state.EpochChanged(ctx); changed {
		return app.onRegistryEpochChanged(ctx, registryEpoch)
	}
	return nil
}

func (app *registryApplication) ExecuteTx(ctx *abci.Context, tx *transaction.Transaction) error {
	state := registryState.NewMutableState(ctx.State())

	switch tx.Method {
	case registry.MethodRegisterEntity:
		var sigEnt entity.SignedEntity
		if err := cbor.Unmarshal(tx.Body, &sigEnt); err != nil {
			return err
		}

		return app.registerEntity(ctx, state, &sigEnt)
	case registry.MethodDeregisterEntity:
		return app.deregisterEntity(ctx, state)
	case registry.MethodRegisterNode:
		var sigNode node.SignedNode
		if err := cbor.Unmarshal(tx.Body, &sigNode); err != nil {
			return err
		}

		return app.registerNode(ctx, state, &sigNode)
	case registry.MethodUnfreezeNode:
		var unfreeze registry.UnfreezeNode
		if err := cbor.Unmarshal(tx.Body, &unfreeze); err != nil {
			return err
		}

		return app.unfreezeNode(ctx, state, &unfreeze)
	case registry.MethodRegisterRuntime:
		var sigRt registry.SignedRuntime
		if err := cbor.Unmarshal(tx.Body, &sigRt); err != nil {
			return err
		}

		params, err := state.ConsensusParameters()
		if err != nil {
			app.logger.Error("RegisterRuntime: failed to fetch consensus parameters",
				"err", err,
			)
			return err
		}

		if !params.DebugAllowRuntimeRegistration {
			return registry.ErrForbidden
		}
		return app.registerRuntime(ctx, state, &sigRt)
	default:
		return registry.ErrInvalidArgument
	}
}

func (app *registryApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx *transaction.Transaction) error {
	return nil
}

func (app *registryApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *registryApplication) FireTimer(*abci.Context, *abci.Timer) error {
	return errors.New("tendermint/registry: unexpected timer")
}

func (app *registryApplication) onRegistryEpochChanged(ctx *abci.Context, registryEpoch epochtime.EpochTime) error {
	state := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	nodes, err := state.Nodes()
	if err != nil {
		app.logger.Error("onRegistryEpochChanged: failed to get nodes",
			"err", err,
		)
		return errors.Wrap(err, "registry: onRegistryEpochChanged: failed to get nodes")
	}

	debondingInterval, err := stakeState.DebondingInterval()
	if err != nil {
		app.logger.Error("onRegistryEpochChanged: failed to get debonding interval",
			"err", err,
		)
		return errors.Wrap(err, "registry: onRegistryEpochChanged: failed to get debonding interval")
	}

	// When a node expires, it is kept around for up to the debonding
	// period and then removed. This is required so that expired nodes
	// can still get slashed while inside the debonding interval as
	// otherwise the nodes could not be resolved.
	var expiredNodes []*node.Node
	for _, node := range nodes {
		if !node.IsExpired(uint64(registryEpoch)) {
			continue
		}

		// Fetch node status to check whether we have already processed the
		// node expiration (this is required so that we don't emit expiration
		// events every epoch).
		var status *registry.NodeStatus
		status, err = state.NodeStatus(node.ID)
		if err != nil {
			return errors.Wrap(err, "registry: onRegistryEpochChanged: couldn't get node status")
		}

		if !status.ExpirationProcessed {
			expiredNodes = append(expiredNodes, node)
			status.ExpirationProcessed = true
			if err = state.SetNodeStatus(node.ID, status); err != nil {
				return errors.Wrap(err, "registry: onRegistryEpochChanged: couldn't set node status")
			}
		}

		// If node has been expired for the debonding interval, finally remove it.
		if epochtime.EpochTime(node.Expiration)+debondingInterval < registryEpoch {
			app.logger.Debug("removing expired node",
				"node_id", node.ID,
			)
			state.RemoveNode(node)
		}
	}

	// Emit the RegistryNodeListEpoch notification event.
	evb := api.NewEventBuilder(app.Name())
	// (Dummy value, should be ignored.)
	evb = evb.Attribute(KeyRegistryNodeListEpoch, []byte("1"))

	if len(expiredNodes) > 0 {
		// Iff any nodes have expired, force-emit the NodesExpired event
		// so the change is picked up.
		evb = evb.Attribute(KeyNodesExpired, cbor.Marshal(expiredNodes))
	}

	ctx.EmitEvent(evb)

	return nil
}

// Perform actual entity registration.
func (app *registryApplication) registerEntity(
	ctx *abci.Context,
	state *registryState.MutableState,
	sigEnt *entity.SignedEntity,
) error {
	ent, err := registry.VerifyRegisterEntityArgs(app.logger, sigEnt, ctx.IsInitChain())
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	params, err := state.ConsensusParameters()
	if err != nil {
		app.logger.Error("RegisterEntity: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if !params.DebugBypassStake {
		if err = stakingState.EnsureSufficientStake(ctx, ent.ID, []staking.ThresholdKind{staking.KindEntity}); err != nil {
			app.logger.Error("RegisterEntity: Insufficent stake",
				"err", err,
				"id", ent.ID,
			)
			return err
		}
	}

	state.CreateEntity(ent, sigEnt)

	app.logger.Debug("RegisterEntity: registered",
		"entity", ent,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEntityRegistered, cbor.Marshal(ent)))

	return nil
}

// Perform actual entity deregistration.
func (app *registryApplication) deregisterEntity(ctx *abci.Context, state *registryState.MutableState) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	id := ctx.TxSigner()

	// Prevent entity deregistration if there are any registered nodes.
	hasNodes, err := state.HasEntityNodes(id)
	if err != nil {
		app.logger.Error("DeregisterEntity: failed to check for nodes",
			"err", err,
		)
		return err
	}
	if hasNodes {
		app.logger.Error("DeregisterEntity: entity still has nodes",
			"entity_id", id,
		)
		return registry.ErrEntityHasNodes
	}

	removedEntity, err := state.RemoveEntity(id)
	if err != nil {
		return err
	}

	if !ctx.IsCheckOnly() {
		app.logger.Debug("DeregisterEntity: complete",
			"entity_id", id,
		)

		tagV := &EntityDeregistration{
			Entity: *removedEntity,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEntityDeregistered, cbor.Marshal(tagV)))
	}

	return nil
}

// Perform actual node registration.
func (app *registryApplication) registerNode(
	ctx *abci.Context,
	state *registryState.MutableState,
	sigNode *node.SignedNode,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Peek into the to-be-verified node to pull out the owning entity ID.
	var untrustedNode node.Node
	if err := cbor.Unmarshal(sigNode.Blob, &untrustedNode); err != nil {
		app.logger.Error("RegisterNode: failed to extract entity",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}
	untrustedEntity, err := state.Entity(untrustedNode.EntityID)
	if err != nil {
		app.logger.Error("RegisterNode: failed to query owning entity",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}

	params, err := state.ConsensusParameters()
	if err != nil {
		app.logger.Error("RegisterNode: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	regRuntimes, err := state.Runtimes()
	if err != nil {
		app.logger.Error("RegisterNode: failed to obtain registry runtimes",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}
	newNode, err := registry.VerifyRegisterNodeArgs(params, app.logger, sigNode, untrustedEntity, ctx.Now(), ctx.IsInitChain(), regRuntimes)
	if err != nil {
		return err
	}

	// Re-check that the entity has at sufficient stake to still be an entity.
	var (
		stakeCache     *stakingState.StakeCache
		numEntityNodes int
	)
	if !params.DebugBypassStake {
		if stakeCache, err = stakingState.NewStakeCache(ctx); err != nil {
			app.logger.Error("RegisterNode: failed to instantiate stake cache",
				"err", err,
			)
			return err
		}

		if err = stakeCache.EnsureSufficientStake(newNode.EntityID, []staking.ThresholdKind{staking.KindEntity}); err != nil {
			app.logger.Error("RegisterNode: insufficent stake, entity no longer valid",
				"err", err,
				"id", newNode.EntityID,
			)
			return err
		}

		if numEntityNodes, err = state.NumEntityNodes(newNode.EntityID); err != nil {
			app.logger.Error("RegisterNode: failed to query existing nodes for entity",
				"err", err,
				"entity", newNode.EntityID,
			)
			return err
		}
	}

	// Ensure node is not expired.
	epoch, err := app.state.GetEpoch(ctx.Ctx(), ctx.BlockHeight()+1)
	if err != nil {
		return err
	}
	if newNode.IsExpired(uint64(epoch)) {
		return registry.ErrNodeExpired
	}

	// Check if node exists.
	existingNode, err := state.Node(newNode.ID)
	isNewNode := err == registry.ErrNoSuchNode
	isExpiredNode := err == nil && existingNode.IsExpired(uint64(epoch))
	if isNewNode || isExpiredNode {
		// Check that the entity has enough stake for this node registration.
		if !params.DebugBypassStake {
			if err = stakeCache.EnsureNodeRegistrationStake(newNode.EntityID, numEntityNodes+1); err != nil {
				app.logger.Error("RegisterNode: insufficient stake for new node",
					"err", err,
					"entity", newNode.EntityID,
				)
				return err
			}
		}

		// Node doesn't exist (or is expired). Create node.
		if err = state.CreateNode(newNode, sigNode); err != nil {
			app.logger.Error("RegisterNode: failed to create node",
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
				app.logger.Error("RegisterNode: failed to get node status",
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
			app.logger.Error("RegisterNode: failed to set node status",
				"err", err,
			)
			return registry.ErrInvalidArgument
		}
	} else if err != nil {
		// Something went horribly wrong, and we failed to query the node.
		app.logger.Error("RegisterNode: failed to query node",
			"err", err,
			"new_node", newNode,
			"existing_node", existingNode,
			"entity", newNode.EntityID,
		)
		return registry.ErrInvalidArgument
	} else {
		// Check that the entity has enough stake for the existing node
		// registrations.
		if !params.DebugBypassStake {
			if err = stakeCache.EnsureNodeRegistrationStake(newNode.EntityID, numEntityNodes); err != nil {
				app.logger.Error("RegisterNode: insufficient stake for existing nodes",
					"err", err,
					"entity", newNode.EntityID,
				)
				return err
			}
		}

		// The node already exists, validate and update the node's entry.
		if err = registry.VerifyNodeUpdate(app.logger, existingNode, newNode); err != nil {
			app.logger.Error("RegisterNode: failed to verify node update",
				"err", err,
				"new_node", newNode,
				"existing_node", existingNode,
				"entity", newNode.EntityID,
			)
			return err
		}
		if err = state.CreateNode(newNode, sigNode); err != nil {
			app.logger.Error("RegisterNode: failed to update node",
				"err", err,
				"node", newNode,
				"entity", newNode.EntityID,
			)
			return registry.ErrBadEntityForNode
		}
	}

	app.logger.Debug("RegisterNode: registered",
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

	// Fetch node descriptor.
	node, err := state.Node(unfreeze.NodeID)
	if err != nil {
		app.logger.Error("UnfreezeNode: failed to fetch node",
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
		app.logger.Error("UnfreezeNode: failed to fetch node status",
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

	app.logger.Debug("UnfreezeNode: unfrozen",
		"node_id", node.ID,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyNodeUnfrozen, cbor.Marshal(node.ID)))

	return nil
}

// Perform actual runtime registration.
func (app *registryApplication) registerRuntime(
	ctx *abci.Context,
	state *registryState.MutableState,
	sigRt *registry.SignedRuntime,
) error {
	rt, err := registry.VerifyRegisterRuntimeArgs(app.logger, sigRt, ctx.IsInitChain())
	if err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
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

	if err = state.CreateRuntime(rt, sigRt); err != nil {
		app.logger.Error("RegisterRuntime: failed to create runtime",
			"err", err,
			"runtime", rt,
			"entity", sigRt.Signature.PublicKey,
		)
		return registry.ErrBadEntityForRuntime
	}

	app.logger.Debug("RegisterRuntime: registered",
		"runtime", rt,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyRuntimeRegistered, cbor.Marshal(rt)))

	return nil
}

// New constructs a new registry application instance.
func New() abci.Application {
	return &registryApplication{
		logger: logging.GetLogger("tendermint/registry"),
	}
}
