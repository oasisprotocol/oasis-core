// Package registry implements the registry application.
package registry

import (
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/runtime"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

var (
	_ abci.Application = (*registryApplication)(nil)
)

type registryApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState
}

func (app *registryApplication) Name() string {
	return api.RegistryAppName
}

func (app *registryApplication) TransactionTag() byte {
	return api.RegistryTransactionTag
}

func (app *registryApplication) Blessed() bool {
	return false
}

func (app *registryApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(api.QueryRegistryGetEntity, &api.QueryGetByIDRequest{}, app.queryGetEntity)
	queryRouter.AddRoute(api.QueryRegistryGetEntities, nil, app.queryGetEntities)
	queryRouter.AddRoute(api.QueryRegistryGetNode, &api.QueryGetByIDRequest{}, app.queryGetNode)
	queryRouter.AddRoute(api.QueryRegistryGetNodes, nil, app.queryGetNodes)
	queryRouter.AddRoute(api.QueryRegistryGetRuntime, &api.QueryGetByIDRequest{}, app.queryGetRuntime)
	queryRouter.AddRoute(api.QueryRegistryGetRuntimes, nil, app.queryGetRuntimes)
}

func (app *registryApplication) OnCleanup() {
}

func (app *registryApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *registryApplication) GetState(height int64) (interface{}, error) {
	return NewImmutableState(app.state, height)
}

func (app *registryApplication) queryGetEntity(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*ImmutableState)
	return state.GetEntityRaw(request.ID)
}

func (app *registryApplication) queryGetEntities(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*ImmutableState)
	return state.GetEntitiesRaw()
}

func (app *registryApplication) queryGetNode(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*ImmutableState)
	return state.GetNodeRaw(request.ID)
}

func (app *registryApplication) queryGetNodes(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*ImmutableState)
	return state.GetNodesRaw()
}

func (app *registryApplication) queryGetRuntime(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*ImmutableState)
	return state.GetRuntimeRaw(request.ID)
}

func (app *registryApplication) queryGetRuntimes(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*ImmutableState)
	return state.GetRuntimesRaw()
}

func (app *registryApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	request := &api.TxRegistry{}
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

func (app *registryApplication) InitChain(request types.RequestInitChain) types.ResponseInitChain {
	return types.ResponseInitChain{}
}

func (app *registryApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) {
}

func (app *registryApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &api.TxRegistry{}
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

func (app *registryApplication) EndBlock(request types.RequestEndBlock) types.ResponseEndBlock {
	return types.ResponseEndBlock{}
}

func (app *registryApplication) FireTimer(*abci.Context, *abci.Timer) {
}

// Execute transaction against given state.
func (app *registryApplication) executeTx(
	ctx *abci.Context,
	tree *iavl.MutableTree,
	tx *api.TxRegistry,
) error {
	state := NewMutableState(tree)

	if tx.TxRegisterEntity != nil {
		return app.registerEntity(ctx, state, &tx.TxRegisterEntity.Entity)
	} else if tx.TxDeregisterEntity != nil {
		return app.deregisterEntity(ctx, state, &tx.TxDeregisterEntity.ID)
	} else if tx.TxRegisterNode != nil {
		return app.registerNode(ctx, state, &tx.TxRegisterNode.Node)
	} else if tx.TxRegisterRuntime != nil {
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
	ent, err := registry.VerifyRegisterEntityArgs(app.logger, sigEnt)
	if err != nil {
		return err
	}

	state.CreateEntity(ent)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("RegisterEntity: registered",
			"entity", ent,
		)

		ctx.EmitData(&api.OutputRegistry{
			OutputRegisterEntity: &api.OutputRegisterEntity{
				Entity: *ent,
			},
		})
		ctx.EmitTag(api.TagRegistryEntityRegistered, ent.ID)
	}

	return nil
}

// Perform actual entity deregistration.
func (app *registryApplication) deregisterEntity(
	ctx *abci.Context,
	state *MutableState,
	sigID *signature.SignedPublicKey,
) error {
	id, err := registry.VerifyDeregisterEntityArgs(app.logger, sigID)
	if err != nil {
		return err
	}

	removedEntity, removedNodes := state.RemoveEntity(id)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("DeregisterEntity: complete",
			"entity_id", id,
		)

		ctx.EmitData(&api.OutputRegistry{
			OutputDeregisterEntity: &api.OutputDeregisterEntity{
				Entity: removedEntity,
				Nodes:  removedNodes,
			},
		})
		ctx.EmitTag(api.TagRegistryEntityDeregistered, id)
	}

	return nil
}

// Perform actual node registration.
func (app *registryApplication) registerNode(
	ctx *abci.Context,
	state *MutableState,
	sigNode *node.SignedNode,
) error {
	node, err := registry.VerifyRegisterNodeArgs(app.logger, sigNode)
	if err != nil {
		return err
	}

	err = state.CreateNode(node)
	if err != nil {
		app.logger.Error("RegisterNode: unknown entity in node registration",
			"node", node,
		)
		return registry.ErrBadEntityForNode
	}

	if !ctx.IsCheckOnly() {
		app.logger.Debug("RegisterNode: registered",
			"node", node,
		)

		ctx.EmitData(&api.OutputRegistry{
			OutputRegisterNode: &api.OutputRegisterNode{
				Node: *node,
			},
		})
		ctx.EmitTag(api.TagRegistryNodeRegistered, node.ID)
	}

	return nil
}

// Perform actual runtime registration.
func (app *registryApplication) registerRuntime(
	ctx *abci.Context,
	state *MutableState,
	sigCon *runtime.SignedRuntime,
) error {
	con, err := registry.VerifyRegisterRuntimeArgs(app.logger, sigCon)
	if err != nil {
		return err
	}

	state.CreateRuntime(con)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("RegisterRuntime: registered",
			"runtime", con,
		)

		ctx.EmitData(&api.OutputRegistry{
			OutputRegisterRuntime: &api.OutputRegisterRuntime{
				Runtime: *con,
			},
		})
		ctx.EmitTag(api.TagRegistryRuntimeRegistered, con.ID)
	}

	return nil
}

// New constructs a new registry application instance.
func New() abci.Application {
	return &registryApplication{
		logger: logging.GetLogger("tendermint/registry"),
	}
}
