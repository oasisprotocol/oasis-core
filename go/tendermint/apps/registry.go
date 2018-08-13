// Package apps implements the Oasis Tendermint applications.
package apps

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
	_ abci.Application = (*RegistryApplication)(nil)
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

// RegistryApplication is a Tendermint-based registry Application.
type RegistryApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState
}

// Name returns the name of the Application.
//
// Note: The name is also used as a prefix for de-multiplexing SetOption
// and Query calls.
func (app *RegistryApplication) Name() string {
	return api.RegistryAppName
}

// TransactionTag returns the transaction tag used to disambiguate
// CheckTx and DeliverTx calls.
func (app *RegistryApplication) TransactionTag() byte {
	return api.RegistryTransactionTag
}

// Blessed returns true iff the Application should be considered
// "blessed", and able to alter the validation set and handle the
// access control related standard ABCI queries.
//
// Only one Application instance may be Blessed per multiplexer
// instance.
func (app *RegistryApplication) Blessed() bool {
	return false
}

// OnRegister is the function that is called when the Application
// is registered with the multiplexer instance.
func (app *RegistryApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

// OnCleanup is the function that is called when the ApplicationServer
// has been halted.
func (app *RegistryApplication) OnCleanup() {
}

// SetOption sets set an application option.
//
// It is expected that the key is prefixed by the application name
// followed by a '/' (eg: `foo/<some key here>`).
func (app *RegistryApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

// Query queries for state.
//
// It is expected that the path is prefixed by the application name
// followed by a '/' (eg: `foo/<some path here>`), or only contains
// the application name if the application does not use paths.
//
// Implementations MUST restrict their state operations to versioned
// Get operations with versions <= BlockHeight.
//
// FIXME: https://github.com/tendermint/iavl/issues/68 hints at
// the possiblity of unbound memory growth (DoS hazzard).
func (app *RegistryApplication) Query(query types.RequestQuery) types.ResponseQuery { // nolint: gocyclo
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

// CheckTx validates a transaction via the mempool.
//
// Implementations MUST only alter the ApplicationState CheckTxTree.
func (app *RegistryApplication) CheckTx(tx []byte) error {
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

// InitChain initializes the blockchain with validators and other
// info from TendermintCore.
func (app *RegistryApplication) InitChain(request types.RequestInitChain) types.ResponseInitChain {
	return types.ResponseInitChain{}
}

// BeginBlock signals the beginning of a block.
func (app *RegistryApplication) BeginBlock(request types.RequestBeginBlock) {
}

// DeliverTx delivers a transaction for full processing.
func (app *RegistryApplication) DeliverTx(tx []byte) (*abci.TxOutput, error) {
	request := &api.TxRegistry{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return nil, errors.Wrap(err, "registry: failed to unmarshal")
	}

	return app.executeTx(app.state.DeliverTxTree(), request, false)
}

// EndBlock signals the end of a block, returning changes to the
// validator set.
func (app *RegistryApplication) EndBlock(request types.RequestEndBlock) types.ResponseEndBlock {
	return types.ResponseEndBlock{}
}

// Perform GetById query.
func (app *RegistryApplication) queryGetByID(stateKey string, data []byte, snapshot *iavl.ImmutableTree) ([]byte, error) {
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
func (app *RegistryApplication) queryGetAll(
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
func (app *RegistryApplication) executeTx(
	state *iavl.MutableTree,
	tx *api.TxRegistry,
	checkOnly bool,
) (*abci.TxOutput, error) {
	if tx.TxRegisterEntity != nil {
		return app.registerEntity(state, checkOnly, &tx.TxRegisterEntity.Entity, &tx.TxRegisterEntity.Signature)
	} else if tx.TxDeregisterEntity != nil {
		return app.deregisterEntity(state, checkOnly, tx.TxDeregisterEntity.ID, &tx.TxDeregisterEntity.Signature)
	} else if tx.TxRegisterNode != nil {
		return app.registerNode(state, checkOnly, &tx.TxRegisterNode.Node, &tx.TxRegisterNode.Signature)
	} else if tx.TxRegisterContract != nil {
		return app.registerContract(state, checkOnly, &tx.TxRegisterContract.Contract, &tx.TxRegisterContract.Signature)
	} else {
		return nil, registry.ErrInvalidArgument
	}
}

// Perform actual entity registration.
func (app *RegistryApplication) registerEntity(
	state *iavl.MutableTree,
	checkOnly bool,
	ent *entity.Entity,
	sig *signature.Signature,
) (*abci.TxOutput, error) {
	// XXX: Ensure ent is well-formed.
	if ent == nil || sig == nil || sig.SanityCheck(ent.ID) != nil {
		app.logger.Error("RegisterEntity: invalid argument(s)",
			"entity", ent,
			"signature", sig,
		)
		return nil, registry.ErrInvalidArgument
	}
	if !sig.Verify(registry.RegisterEntitySignatureContext, ent.ToSignable()) {
		return nil, registry.ErrInvalidSignature
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
func (app *RegistryApplication) deregisterEntity(
	state *iavl.MutableTree,
	checkOnly bool,
	id signature.PublicKey,
	sig *signature.Signature,
) (*abci.TxOutput, error) {
	if sig == nil || sig.SanityCheck(id) != nil {
		app.logger.Error("DeregisterEntity: invalid argument(s)",
			"entity_id", id,
			"signature", sig,
		)
		return nil, registry.ErrInvalidArgument
	}
	if !sig.Verify(registry.DeregisterEntitySignatureContext, id) {
		app.logger.Error("DeregisterEntity: invalid signature",
			"entity_id", id,
			"signature", sig,
		)
		return nil, registry.ErrInvalidSignature
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
func (app *RegistryApplication) registerNode(
	state *iavl.MutableTree,
	checkOnly bool,
	node *node.Node,
	sig *signature.Signature,
) (*abci.TxOutput, error) {
	// XXX: Ensure node is well-formed.
	if node == nil || sig == nil || sig.SanityCheck(node.EntityID) != nil {
		app.logger.Error("RegisterNode: invalid argument(s)",
			"node", node,
			"signature", sig,
		)
		return nil, registry.ErrInvalidArgument
	}
	if !sig.Verify(registry.RegisterNodeSignatureContext, node.ToSignable()) {
		return nil, registry.ErrInvalidSignature
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
func (app *RegistryApplication) registerContract(
	state *iavl.MutableTree,
	checkOnly bool,
	con *contract.Contract,
	sig *signature.Signature,
) (*abci.TxOutput, error) {
	// XXX: Ensure contact is well-formed.
	if con == nil || sig == nil || sig.SanityCheck(con.ID) != nil {
		app.logger.Error("RegisterContract: invalid argument(s)",
			"contract", con,
			"signature", sig,
		)
		return nil, registry.ErrInvalidArgument
	}
	if !sig.Verify(registry.RegisterContractSignatureContext, con.ToSignable()) {
		return nil, registry.ErrInvalidSignature
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

// NewRegistryApplication constructs a new RegistryApplication instance.
func NewRegistryApplication() abci.Application {
	return &RegistryApplication{
		logger: logging.GetLogger("RegistryApplication"),
	}
}
