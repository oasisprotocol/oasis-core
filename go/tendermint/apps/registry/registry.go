// Package registry implements the registry application.
package registry

import (
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	tmcmn "github.com/tendermint/tendermint/libs/common"

	"github.com/oasislabs/ekiden/go/common"
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

const (
	// Entity map state key prefix.
	stateEntityMap = "registry/entity/%s"

	// Node map state key prefix.
	stateNodeMap = "registry/node/%s"
	// Node by entity map state key prefix.
	stateNodeByEntityMap = "registry/node_by_entity/%s/%s"

	// Contract map state key prefix.
	stateContractMap = "registry/contract/%s"

	// Highest hex-encoded node/entity/contract identifier.
	// TODO: Should we move this to common?
	lastID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
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

func (app *registryApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *registryApplication) OnCleanup() {
}

func (app *registryApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *registryApplication) Query(query types.RequestQuery) types.ResponseQuery { // nolint: gocyclo
	// Get state snapshot based on specified version.
	version := query.GetHeight()
	if version <= 0 || version > app.state.BlockHeight() {
		version = app.state.BlockHeight()
	}

	snapshot, err := app.state.DeliverTxTree().GetImmutable(version)
	if err != nil {
		return types.ResponseQuery{
			Code: api.CodeTransactionFailed.ToInt(),
			Info: err.Error(),
		}
	}

	var response []byte
	switch query.GetPath() {
	case api.QueryRegistryGetEntity:
		response, err = app.queryGetByID(stateEntityMap, query.GetData(), snapshot)
	case api.QueryRegistryGetEntities:
		response, err = app.queryGetAll(stateEntityMap, snapshot, &entity.Entity{})
	case api.QueryRegistryGetNode:
		response, err = app.queryGetByID(stateNodeMap, query.GetData(), snapshot)
	case api.QueryRegistryGetNodes:
		response, err = app.queryGetAll(stateNodeMap, snapshot, &node.Node{})
	case api.QueryRegistryGetContract:
		response, err = app.queryGetByID(stateContractMap, query.GetData(), snapshot)
	case api.QueryRegistryGetContracts:
		response, err = app.queryGetAll(stateContractMap, snapshot, &contract.Contract{})
	default:
		return types.ResponseQuery{
			Code: api.CodeInvalidQuery.ToInt(),
		}
	}

	if err != nil {
		return types.ResponseQuery{
			Code: api.CodeTransactionFailed.ToInt(),
			Info: err.Error(),
		}
	}
	if response == nil {
		return types.ResponseQuery{
			Code: api.CodeNotFound.ToInt(),
		}
	}

	return types.ResponseQuery{
		Code:  api.CodeOK.ToInt(),
		Value: response,
	}
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

// Perform GetById query.
func (app *registryApplication) queryGetByID(stateKey string, data []byte, snapshot *iavl.ImmutableTree) ([]byte, error) {
	request := &api.QueryGetByIDRequest{}
	if err := cbor.Unmarshal(data, request); err != nil {
		return nil, registry.ErrInvalidArgument
	}

	_, value := snapshot.Get(
		[]byte(fmt.Sprintf(stateKey, request.ID.String())),
	)

	return value, nil
}

// Perform GetAll query.
func (app *registryApplication) queryGetAll(
	stateKey string,
	snapshot *iavl.ImmutableTree,
	item common.Cloneable,
) ([]byte, error) {
	var items []interface{}
	snapshot.IterateRangeInclusive(
		[]byte(fmt.Sprintf(stateKey, "")),
		[]byte(fmt.Sprintf(stateKey, lastID)),
		true,
		func(key, value []byte, version int64) bool {
			itemCopy := item.Clone()
			cbor.MustUnmarshal(value, &itemCopy)

			items = append(items, itemCopy)
			return false
		},
	)

	value := cbor.Marshal(items)

	return value, nil
}

// Execute transaction against given state.
func (app *registryApplication) executeTx(
	state *iavl.MutableTree,
	tx *api.TxRegistry,
	checkOnly bool,
) (*abci.TxOutput, error) {
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
	state *iavl.MutableTree,
	checkOnly bool,
	sigEnt *entity.SignedEntity,
) (*abci.TxOutput, error) {
	ent, err := registry.VerifyRegisterEntityArgs(app.logger, sigEnt)
	if err != nil {
		return nil, err
	}

	if checkOnly {
		return nil, nil
	}

	state.Set(
		[]byte(fmt.Sprintf(stateEntityMap, ent.ID.String())),
		ent.MarshalCBOR(),
	)

	app.logger.Debug("RegisterEntity: registered",
		"entity", ent,
	)

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
	state *iavl.MutableTree,
	checkOnly bool,
	sigID *signature.SignedPublicKey,
) (*abci.TxOutput, error) {
	id, err := registry.VerifyDeregisterEntityArgs(app.logger, sigID)
	if err != nil {
		return nil, err
	}

	if checkOnly {
		return nil, nil
	}

	var removedEntity entity.Entity
	var removedNodes []node.Node
	data, removed := state.Remove([]byte(fmt.Sprintf(stateEntityMap, id.String())))
	if removed {
		// Remove any associated nodes.
		state.IterateRangeInclusive(
			[]byte(fmt.Sprintf(stateNodeByEntityMap, id.String(), "")),
			[]byte(fmt.Sprintf(stateNodeByEntityMap, id.String(), lastID)),
			true,
			func(key, value []byte, version int64) bool {
				// Remove all dependent nodes.
				nodeData, _ := state.Remove([]byte(fmt.Sprintf(stateNodeMap, value)))
				state.Remove([]byte(fmt.Sprintf(stateNodeByEntityMap, id.String(), value)))

				var removedNode node.Node
				cbor.MustUnmarshal(nodeData, &removedNode)

				removedNodes = append(removedNodes, removedNode)
				return false
			},
		)

		cbor.MustUnmarshal(data, &removedEntity)
	}

	app.logger.Debug("DeregisterEntity: complete",
		"entity_id", id,
	)

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
	state *iavl.MutableTree,
	checkOnly bool,
	sigNode *node.SignedNode,
) (*abci.TxOutput, error) {
	node, err := registry.VerifyRegisterNodeArgs(app.logger, sigNode)
	if err != nil {
		return nil, err
	}

	// Ensure that the entity exists.
	_, ent := state.Get(
		[]byte(fmt.Sprintf(stateEntityMap, node.EntityID.String())),
	)
	if ent == nil {
		app.logger.Error("RegisterNode: unknown entity in node registration",
			"node", node,
		)
		return nil, registry.ErrBadEntityForNode
	}

	if checkOnly {
		return nil, nil
	}

	state.Set(
		[]byte(fmt.Sprintf(stateNodeMap, node.ID.String())),
		node.MarshalCBOR(),
	)
	state.Set(
		[]byte(fmt.Sprintf(stateNodeByEntityMap, node.EntityID.String(), node.ID.String())),
		[]byte(node.ID.String()),
	)

	app.logger.Debug("RegisterNode: registered",
		"node", node,
	)

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
	state *iavl.MutableTree,
	checkOnly bool,
	sigCon *contract.SignedContract,
) (*abci.TxOutput, error) {
	con, err := registry.VerifyRegisterContractArgs(app.logger, sigCon)
	if err != nil {
		return nil, err
	}

	if checkOnly {
		return nil, nil
	}

	state.Set(
		[]byte(fmt.Sprintf(stateContractMap, con.ID.String())),
		con.MarshalCBOR(),
	)

	app.logger.Debug("RegisterContract: registered",
		"contract", con,
	)

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
