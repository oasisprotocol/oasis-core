// Package registry implements the registry application.
package registry

import (
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
	stakingapp "github.com/oasislabs/oasis-core/go/tendermint/apps/staking"
)

var _ abci.Application = (*registryApplication)(nil)

type registryApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.Backend

	cfg *registry.Config
}

func (app *registryApplication) Name() string {
	return AppName
}

func (app *registryApplication) TransactionTag() byte {
	return TransactionTag
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

func (app *registryApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *registryApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *registryApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// XXX: With PR#1889 this can be a differnet interval.
	if changed, registryEpoch := app.state.EpochChanged(app.timeSource); changed {
		return app.onRegistryEpochChanged(ctx, registryEpoch)
	}
	return nil
}

func (app *registryApplication) ExecuteTx(ctx *abci.Context, rawTx []byte) error {
	var tx Tx
	if err := cbor.Unmarshal(rawTx, &tx); err != nil {
		app.logger.Error("failed to unmarshal",
			"tx", hex.EncodeToString(rawTx),
		)
		return errors.Wrap(err, "registry: failed to unmarshal")
	}

	state := NewMutableState(ctx.State())

	if tx.TxRegisterEntity != nil {
		return app.registerEntity(ctx, state, &tx.TxRegisterEntity.Entity)
	} else if tx.TxDeregisterEntity != nil {
		return app.deregisterEntity(ctx, state, &tx.TxDeregisterEntity.Timestamp)
	} else if tx.TxRegisterNode != nil {
		return app.registerNode(ctx, state, &tx.TxRegisterNode.Node)
	} else if tx.TxRegisterRuntime != nil {
		if !app.cfg.DebugAllowRuntimeRegistration {
			return registry.ErrForbidden
		}
		return app.registerRuntime(ctx, state, &tx.TxRegisterRuntime.Runtime)
	}
	return registry.ErrInvalidArgument
}

func (app *registryApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *registryApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *registryApplication) FireTimer(*abci.Context, *abci.Timer) error {
	return errors.New("tendermint/registry: unexpected timer")
}

func (app *registryApplication) onRegistryEpochChanged(ctx *abci.Context, registryEpoch epochtime.EpochTime) error {
	state := NewMutableState(ctx.State())

	nodes, err := state.GetNodes()
	if err != nil {
		app.logger.Error("onRegistryEpochChanged: failed to get nodes",
			"err", err,
		)
		return errors.Wrap(err, "registry: onRegistryEpochChanged: failed to get nodes")
	}

	var expiredNodes []*node.Node
	for _, node := range nodes {
		if epochtime.EpochTime(node.Expiration) >= registryEpoch {
			continue
		}
		expiredNodes = append(expiredNodes, node)
		state.removeNode(node)
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
	state *MutableState,
	sigEnt *entity.SignedEntity,
) error {
	ent, err := registry.VerifyRegisterEntityArgs(app.logger, sigEnt, ctx.IsInitChain())
	if err != nil {
		return err
	}

	if !ctx.IsCheckOnly() && !ctx.IsInitChain() {
		err = registry.VerifyTimestamp(ent.RegistrationTime, uint64(ctx.Now().Unix()))
		if err != nil {
			app.logger.Error("RegisterEntity: INVALID TIMESTAMP",
				"entity_timestamp", ent.RegistrationTime,
				"now", uint64(ctx.Now().Unix()),
			)
			return err
		}
	}

	if !app.cfg.DebugBypassStake {
		if err = stakingapp.EnsureSufficientStake(ctx, ent.ID, []staking.ThresholdKind{staking.KindEntity}); err != nil {
			app.logger.Error("RegisterEntity: Insufficent stake",
				"err", err,
				"id", ent.ID,
			)
			return err
		}
	}

	state.createEntity(ent, sigEnt)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("RegisterEntity: registered",
			"entity", ent,
		)

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEntityRegistered, cbor.Marshal(ent)))
	}

	return nil
}

// Perform actual entity deregistration.
func (app *registryApplication) deregisterEntity(
	ctx *abci.Context,
	state *MutableState,
	sigTimestamp *signature.Signed,
) error {
	id, timestamp, err := registry.VerifyDeregisterEntityArgs(app.logger, sigTimestamp)
	if err != nil {
		return err
	}

	if !ctx.IsCheckOnly() {
		err = registry.VerifyTimestamp(timestamp, uint64(ctx.Now().Unix()))
		if err != nil {
			app.logger.Error("DeregisterEntity: INVALID TIMESTAMP",
				"timestamp", timestamp,
				"now", uint64(ctx.Now().Unix()),
			)
			return err
		}
	}

	removedEntity, removedNodes := state.removeEntity(id)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("DeregisterEntity: complete",
			"entity_id", id,
		)

		tagV := &EntityDeregistration{
			Entity: removedEntity,
			Nodes:  removedNodes,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEntityDeregistered, cbor.Marshal(tagV)))
	}

	return nil
}

// Perform actual node registration.
func (app *registryApplication) registerNode(
	ctx *abci.Context,
	state *MutableState,
	sigNode *node.SignedNode,
) error {
	// Peek into the to-be-verified node to pull out the owning entity ID.
	var untrustedNode node.Node
	if err := untrustedNode.UnmarshalCBOR(sigNode.Blob); err != nil {
		app.logger.Error("RegisterNode: failed to extract entity",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}
	untrustedEntity, err := state.getEntity(untrustedNode.EntityID)
	if err != nil {
		app.logger.Error("RegisterNode: failed to query owning entity",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}

	kmOperator := state.getKeyManagerOperator()
	regRuntimes, err := state.GetRuntimes()
	if err != nil {
		app.logger.Error("RegisterNode: failed to obtain registry runtimes",
			"err", err,
			"signed_node", sigNode,
		)
		return err
	}
	newNode, err := registry.VerifyRegisterNodeArgs(app.cfg, app.logger, sigNode, untrustedEntity, ctx.Now(), ctx.IsInitChain(), kmOperator, regRuntimes)
	if err != nil {
		return err
	}

	if !ctx.IsCheckOnly() && !ctx.IsInitChain() {
		err = registry.VerifyTimestamp(newNode.RegistrationTime, uint64(ctx.Now().Unix()))
		if err != nil {
			app.logger.Error("RegisterNode: INVALID TIMESTAMP",
				"node_timestamp", newNode.RegistrationTime,
				"now", uint64(ctx.Now().Unix()),
			)
			return err
		}
	}

	// Re-check that the entity has at least sufficient stake to still be an
	// entity.  The node thresholds should be enforced in the scheduler.
	if !app.cfg.DebugBypassStake {
		if err = stakingapp.EnsureSufficientStake(ctx, newNode.EntityID, []staking.ThresholdKind{staking.KindEntity}); err != nil {
			app.logger.Error("RegisterNode: Insufficent stake",
				"err", err,
				"id", newNode.EntityID,
			)
			return err
		}
	}

	// Ensure node is not expired.
	epoch, err := app.timeSource.GetEpoch(context.Background(), app.state.BlockHeight())
	if err != nil {
		return err
	}
	if epochtime.EpochTime(newNode.Expiration) < epoch {
		return registry.ErrNodeExpired
	}

	// Check if node exists
	existingNode, err := state.GetNode(newNode.ID)
	if err != nil {
		if err == registry.ErrNoSuchNode {
			// Node doesn't exist. Create node.
			err = state.createNode(newNode, sigNode)
			if err != nil {
				app.logger.Error("RegisterNode: failed to create node",
					"err", err,
					"node", newNode,
					"entity", newNode.EntityID,
				)
				return registry.ErrBadEntityForNode
			}
		} else {
			app.logger.Error("RegisterNode: failed to register node",
				"err", err,
				"new_node", newNode,
				"existing_node", existingNode,
				"entity", newNode.EntityID,
			)
		}
	} else {
		err := registry.VerifyNodeUpdate(app.logger, existingNode, newNode)
		if err != nil {
			app.logger.Error("RegisterNode: failed to verify node update",
				"err", err,
				"new_node", newNode,
				"existing_node", existingNode,
				"entity", newNode.EntityID,
			)
			return err
		}
		err = state.createNode(newNode, sigNode)
		if err != nil {
			app.logger.Error("RegisterNode: failed to update node",
				"err", err,
				"node", newNode,
				"entity", newNode.EntityID,
			)
			return registry.ErrBadEntityForNode
		}
	}

	if !ctx.IsCheckOnly() {
		app.logger.Debug("RegisterNode: registered",
			"node", newNode,
			"roles", newNode.Roles,
		)

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyNodeRegistered, cbor.Marshal(newNode)))
	}

	return nil
}

// Perform actual runtime registration.
func (app *registryApplication) registerRuntime(
	ctx *abci.Context,
	state *MutableState,
	sigRt *registry.SignedRuntime,
) error {
	rt, err := registry.VerifyRegisterRuntimeArgs(app.logger, sigRt, ctx.IsInitChain())
	if err != nil {
		return err
	}

	if !ctx.IsCheckOnly() && !ctx.IsInitChain() {
		err = registry.VerifyTimestamp(rt.RegistrationTime, uint64(ctx.Now().Unix()))
		if err != nil {
			app.logger.Error("RegisterRuntime: INVALID TIMESTAMP",
				"runtime_timestamp", rt.RegistrationTime,
				"now", uint64(ctx.Now().Unix()),
			)
			return err
		}
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

	if err = state.createRuntime(rt, sigRt); err != nil {
		app.logger.Error("RegisterRuntime: failed to create runtime",
			"err", err,
			"runtime", rt,
			"entity", sigRt.Signature.PublicKey,
		)
		return registry.ErrBadEntityForRuntime
	}

	if !ctx.IsCheckOnly() {
		app.logger.Debug("RegisterRuntime: registered",
			"runtime", rt,
		)

		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyRuntimeRegistered, cbor.Marshal(rt)))
	}

	return nil
}

// New constructs a new registry application instance.
func New(timeSource epochtime.Backend, cfg *registry.Config) abci.Application {
	return &registryApplication{
		logger:     logging.GetLogger("tendermint/registry"),
		timeSource: timeSource,
		cfg:        cfg,
	}
}
