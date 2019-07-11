// Package registry implements the registry application.
package registry

import (
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	staking "github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	stakingapp "github.com/oasislabs/ekiden/go/tendermint/apps/staking"
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

func (app *registryApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(QueryGetEntity, api.QueryGetByIDRequest{}, app.queryGetEntity)
	queryRouter.AddRoute(QueryGetEntities, nil, app.queryGetEntities)
	queryRouter.AddRoute(QueryGetNode, api.QueryGetByIDRequest{}, app.queryGetNode)
	queryRouter.AddRoute(QueryGetNodes, nil, app.queryGetNodes)
	queryRouter.AddRoute(QueryGetRuntime, api.QueryGetByIDRequest{}, app.queryGetRuntime)
	queryRouter.AddRoute(QueryGetRuntimes, nil, app.queryGetRuntimes)
}

func (app *registryApplication) OnCleanup() {
}

func (app *registryApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *registryApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *registryApplication) queryGetEntity(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*immutableState)
	return state.getEntityRaw(request.ID)
}

func (app *registryApplication) queryGetEntities(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.getEntitiesRaw()
}

func (app *registryApplication) queryGetNode(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*immutableState)
	return state.getNodeRaw(request.ID)
}

func (app *registryApplication) queryGetNodes(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.getNodesRaw()
}

func (app *registryApplication) queryGetRuntime(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*immutableState)
	return state.getRuntimeRaw(request.ID)
}

func (app *registryApplication) queryGetRuntimes(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.getRuntimesRaw()
}

func (app *registryApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("CheckTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "registry: failed to unmarshal")
	}

	if err := app.executeTx(ctx, app.state.CheckTxTree(), request); err != nil {
		return err
	}

	return nil
}

func (app *registryApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *registryApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.Registry

	app.logger.Debug("InitChain: Genesis state",
		"state", string(json.Marshal(st)),
	)

	state := NewMutableState(app.state.DeliverTxTree())
	for _, v := range st.Entities {
		app.logger.Debug("InitChain: Registering genesis entity",
			"entity", v.Signature.PublicKey,
		)
		if err := app.registerEntity(ctx, state, v); err != nil {
			app.logger.Error("InitChain: failed to register entity",
				"err", err,
				"entity", v,
			)
			return errors.Wrap(err, "registry: genesis entity registration failure")
		}
	}
	for _, v := range st.Runtimes {
		app.logger.Debug("InitChain: Registering genesis runtime",
			"runtime_owner", v.Signature.PublicKey,
		)
		if err := app.registerRuntime(ctx, state, v); err != nil {
			app.logger.Error("InitChain: failed to register runtime",
				"err", err,
				"runtime", v,
			)
			return errors.Wrap(err, "registry: genesis runtime registration failure")
		}
	}
	for _, v := range st.Nodes {
		app.logger.Debug("InitChain: Registring genesis node",
			"node_owner", v.Signature.PublicKey,
		)
		if err := app.registerNode(ctx, state, v); err != nil {
			app.logger.Error("InitChain: failed to register node",
				"err", err,
				"node", v,
			)
			return errors.Wrap(err, "registry: genesis node registration failure")
		}
	}

	if len(st.Entities) > 0 || len(st.Runtimes) > 0 || len(st.Nodes) > 0 {
		ctx.EmitTag([]byte(app.Name()), api.TagAppNameValue)
	}

	return nil
}

func (app *registryApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	if changed, epoch := app.state.EpochChanged(app.timeSource); changed {
		return app.onEpochChange(ctx, epoch)
	}
	return nil
}

func (app *registryApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "registry: failed to unmarshal")
	}

	return app.executeTx(ctx, app.state.DeliverTxTree(), request)
}

func (app *registryApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *registryApplication) EndBlock(request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *registryApplication) FireTimer(*abci.Context, *abci.Timer) {
}

func (app *registryApplication) onEpochChange(ctx *abci.Context, epoch epochtime.EpochTime) error {
	state := NewMutableState(app.state.DeliverTxTree())

	nodes, err := state.GetNodes()
	if err != nil {
		app.logger.Error("onEpochChange: failed to get nodes",
			"err", err,
		)
		return errors.Wrap(err, "registry: onEpochChange: failed to get nodes")
	}

	var expiredNodes []*node.Node
	for _, node := range nodes {
		if epochtime.EpochTime(node.Expiration) >= epoch {
			continue
		}
		expiredNodes = append(expiredNodes, node)
		state.removeNode(node)
	}
	if len(expiredNodes) == 0 {
		return nil
	}

	// Iff any nodes have expired, force-emit the application tag so
	// the change is picked up.
	ctx.EmitTag([]byte(app.Name()), api.TagAppNameValue)
	ctx.EmitTag(TagNodesExpired, cbor.Marshal(expiredNodes))

	return nil
}

// Execute transaction against given state.
func (app *registryApplication) executeTx(
	ctx *abci.Context,
	tree *iavl.MutableTree,
	tx *Tx,
) error {
	state := NewMutableState(tree)

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
	} else {
		return registry.ErrInvalidArgument
	}
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
		if err = stakingapp.EnsureSufficientStake(app.state, ctx, ent.ID, []staking.ThresholdKind{staking.KindEntity}); err != nil {
			app.logger.Error("RegisterEntity: Insufficent stake",
				"err", err,
				"id", ent.ID,
			)
			return err
		}
	}

	state.createEntity(ent)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("RegisterEntity: registered",
			"entity", ent,
		)

		ctx.EmitTag(TagEntityRegistered, ent.ID)
		ctx.EmitData(&Output{
			OutputRegisterEntity: &OutputRegisterEntity{
				Entity: *ent,
			},
		})
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

		ctx.EmitData(&Output{
			OutputDeregisterEntity: &OutputDeregisterEntity{
				Entity: removedEntity,
				Nodes:  removedNodes,
			},
		})
	}

	return nil
}

// Perform actual node registration.
func (app *registryApplication) registerNode(
	ctx *abci.Context,
	state *MutableState,
	sigNode *node.SignedNode,
) error {
	node, err := registry.VerifyRegisterNodeArgs(app.logger, sigNode, ctx.Now(), ctx.IsInitChain())
	if err != nil {
		return err
	}

	if !ctx.IsCheckOnly() && !ctx.IsInitChain() {
		err = registry.VerifyTimestamp(node.RegistrationTime, uint64(ctx.Now().Unix()))
		if err != nil {
			app.logger.Error("RegisterNode: INVALID TIMESTAMP",
				"node_timestamp", node.RegistrationTime,
				"now", uint64(ctx.Now().Unix()),
			)
			return err
		}
	}

	// Re-check that the entity has at least sufficient stake to still be an
	// entity.  The node thresholds should be enforced in the scheduler.
	if !app.cfg.DebugBypassStake {
		if err = stakingapp.EnsureSufficientStake(app.state, ctx, node.EntityID, []staking.ThresholdKind{staking.KindEntity}); err != nil {
			app.logger.Error("RegisterNode: Insufficent stake",
				"err", err,
				"id", node.EntityID,
			)
			return err
		}
	}

	// Ensure node is not expired.
	epoch, err := app.timeSource.GetEpoch(context.Background(), app.state.BlockHeight())
	if err != nil {
		return err
	}
	if epochtime.EpochTime(node.Expiration) < epoch {
		return registry.ErrNodeExpired
	}

	err = state.createNode(node)
	if err != nil {
		app.logger.Error("RegisterNode: failed to create node",
			"err", err,
			"node", node,
			"entity", node.EntityID,
		)
		return registry.ErrBadEntityForNode
	}

	if !ctx.IsCheckOnly() {
		app.logger.Debug("RegisterNode: registered",
			"node", node,
		)

		ctx.EmitData(&Output{
			OutputRegisterNode: &OutputRegisterNode{
				Node: *node,
			},
		})
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

	if err = state.createRuntime(rt, sigRt.Signature.PublicKey); err != nil {
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

		ctx.EmitTag(TagRuntimeRegistered, rt.ID)
		ctx.EmitData(&Output{
			OutputRegisterRuntime: &OutputRegisterRuntime{
				Runtime: *rt,
			},
		})
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
