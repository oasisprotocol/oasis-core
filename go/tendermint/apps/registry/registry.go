// Package registry implements the registry application.
package registry

import (
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	tmcmn "github.com/tendermint/tendermint/libs/common"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
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
	queryRouter.AddRoute(api.QueryRegistryGetContract, &api.QueryGetByIDRequest{}, app.queryGetContract)
	queryRouter.AddRoute(api.QueryRegistryGetContracts, nil, app.queryGetContracts)
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

func (app *registryApplication) queryGetContract(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*ImmutableState)
	return state.GetContractRaw(request.ID)
}

func (app *registryApplication) queryGetContracts(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*ImmutableState)
	return state.GetContractsRaw()
}

func (app *registryApplication) CheckTx(tx []byte) error {
	request := &api.TxRegistry{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("CheckTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "registry: failed to unmarshal")
	}

	if _, err := app.executeTx(app.state.CheckTxTree(), request, true); err != nil {
		return err
	}

	return nil
}

func (app *registryApplication) InitChain(request types.RequestInitChain) types.ResponseInitChain {
	return types.ResponseInitChain{}
}

func (app *registryApplication) BeginBlock(request types.RequestBeginBlock) {
}

func (app *registryApplication) DeliverTx(tx []byte) (*abci.TxOutput, error) {
	request := &api.TxRegistry{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return nil, errors.Wrap(err, "registry: failed to unmarshal")
	}

	return app.executeTx(app.state.DeliverTxTree(), request, false)
}

func (app *registryApplication) EndBlock(request types.RequestEndBlock) types.ResponseEndBlock {
	return types.ResponseEndBlock{}
}

// Execute transaction against given state.
func (app *registryApplication) executeTx(
	tree *iavl.MutableTree,
	tx *api.TxRegistry,
	checkOnly bool,
) (*abci.TxOutput, error) {
	state := NewMutableState(tree)

	if tx.TxRegisterEntity != nil {
		return app.registerEntity(state, checkOnly, &tx.TxRegisterEntity.Entity)
	} else if tx.TxDeregisterEntity != nil {
		return app.deregisterEntity(state, checkOnly, &tx.TxDeregisterEntity.ID)
	} else if tx.TxRegisterNode != nil {
		return app.registerNode(state, checkOnly, &tx.TxRegisterNode.Node)
	} else if tx.TxRegisterContract != nil {
		return app.registerContract(state, checkOnly, &tx.TxRegisterContract.Contract)
	} else {
		return nil, registry.ErrInvalidArgument
	}
}

// Perform actual entity registration.
func (app *registryApplication) registerEntity(
	state *MutableState,
	checkOnly bool,
	sigEnt *entity.SignedEntity,
) (*abci.TxOutput, error) {
	ent, err := registry.VerifyRegisterEntityArgs(app.logger, sigEnt)
	if err != nil {
		return nil, err
	}

	state.CreateEntity(ent)

	if !checkOnly {
		app.logger.Debug("RegisterEntity: registered",
			"entity", ent,
		)
	}

	return &abci.TxOutput{
		Data: &api.OutputRegistry{
			OutputRegisterEntity: &api.OutputRegisterEntity{
				Entity: *ent,
			},
		},
		Tags: []tmcmn.KVPair{
			{api.TagRegistryEntityRegistered, ent.ID},
		},
	}, nil
}

// Perform actual entity deregistration.
func (app *registryApplication) deregisterEntity(
	state *MutableState,
	checkOnly bool,
	sigID *signature.SignedPublicKey,
) (*abci.TxOutput, error) {
	id, err := registry.VerifyDeregisterEntityArgs(app.logger, sigID)
	if err != nil {
		return nil, err
	}

	removedEntity, removedNodes := state.RemoveEntity(id)

	if !checkOnly {
		app.logger.Debug("DeregisterEntity: complete",
			"entity_id", id,
		)
	}

	return &abci.TxOutput{
		Data: &api.OutputRegistry{
			OutputDeregisterEntity: &api.OutputDeregisterEntity{
				Entity: removedEntity,
				Nodes:  removedNodes,
			},
		},
		Tags: []tmcmn.KVPair{
			{api.TagRegistryEntityDeregistered, id},
		},
	}, nil
}

// Perform actual node registration.
func (app *registryApplication) registerNode(
	state *MutableState,
	checkOnly bool,
	sigNode *node.SignedNode,
) (*abci.TxOutput, error) {
	node, err := registry.VerifyRegisterNodeArgs(app.logger, sigNode)
	if err != nil {
		return nil, err
	}

	err = state.CreateNode(node)
	if err != nil {
		app.logger.Error("RegisterNode: unknown entity in node registration",
			"node", node,
		)
		return nil, registry.ErrBadEntityForNode
	}

	if !checkOnly {
		app.logger.Debug("RegisterNode: registered",
			"node", node,
		)
	}

	return &abci.TxOutput{
		Data: &api.OutputRegistry{
			OutputRegisterNode: &api.OutputRegisterNode{
				Node: *node,
			},
		},
		Tags: []tmcmn.KVPair{
			{api.TagRegistryNodeRegistered, node.ID},
		},
	}, nil
}

// Perform actual contract registration.
func (app *registryApplication) registerContract(
	state *MutableState,
	checkOnly bool,
	sigCon *contract.SignedContract,
) (*abci.TxOutput, error) {
	con, err := registry.VerifyRegisterContractArgs(app.logger, sigCon)
	if err != nil {
		return nil, err
	}

	state.CreateContract(con)

	if !checkOnly {
		app.logger.Debug("RegisterContract: registered",
			"contract", con,
		)
	}

	return &abci.TxOutput{
		Data: &api.OutputRegistry{
			OutputRegisterContract: &api.OutputRegisterContract{
				Contract: *con,
			},
		},
		Tags: []tmcmn.KVPair{
			{api.TagRegistryContractRegistered, con.ID},
		},
	}, nil
}

// New constructs a new registry application instance.
func New() abci.Application {
	return &registryApplication{
		logger: logging.GetLogger("tendermint/registry"),
	}
}
