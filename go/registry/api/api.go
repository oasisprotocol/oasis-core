// Package api implements the runtime and entity registry APIs.
package api

import (
	"errors"

	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
)

var (
	// RegisterEntitySignatureContext is the context used for entity
	// registration.
	RegisterEntitySignatureContext = []byte("EkEntReg")

	// DeregisterEntitySignatureContext is the context used for entity
	// deregistration.
	DeregisterEntitySignatureContext = []byte("EkEDeReg")

	// RegisterNodeSignatureContext is the context used for node
	// registration.
	RegisterNodeSignatureContext = []byte("EkNodReg")

	// RegisterContractSignatureContext is the context used for contract
	// registration.
	RegisterContractSignatureContext = []byte("EkConReg")

	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New("registry: invalid argument")

	// ErrInvalidSignature is the error returned on an invalid signature.
	ErrInvalidSignature = errors.New("registry: invalid signature")

	// ErrBadEntityForNode is the error returned when a node registration
	// with an unknown entity is attempted.
	ErrBadEntityForNode = errors.New("registry: unknown entity in node registration")

	// ErrNoSuchEntity is the error returned when an entity does not exist.
	ErrNoSuchEntity = errors.New("registry: no such entity")

	// ErrNoSuchNode is the error returned when an node does not exist.
	ErrNoSuchNode = errors.New("registry: no such node")

	// ErrNoSuchContract is the error returned when an contract does not exist.
	ErrNoSuchContract = errors.New("registry: no such contract")
)

// Backend is a registry implementation.
type Backend interface {
	// RegisterEntity registers and or updates an entity with the registry.
	//
	// The signature should be made using RegisterEntitySignatureContext.
	RegisterEntity(context.Context, *entity.SignedEntity) error

	// DeregisterEntity deregisters an entity.
	//
	// The signature should be made using DeregisterEntitySignatureContext.
	DeregisterEntity(context.Context, *signature.SignedPublicKey) error

	// GetEntity gets an entity by ID.
	GetEntity(context.Context, signature.PublicKey) (*entity.Entity, error)

	// GetEntities gets a list of all registered entities.
	GetEntities(context.Context) ([]*entity.Entity, error)

	// WatchEntities returns a channel that produces a stream of
	// EntityEvent on entity registration changes.
	WatchEntities() (<-chan *EntityEvent, *pubsub.Subscription)

	// RegisterNode registers and or updates a node with the registry.
	//
	// The signature should be made using RegisterNodeSignatureContext.
	RegisterNode(context.Context, *node.SignedNode) error

	// GetNode gets a node by ID.
	GetNode(context.Context, signature.PublicKey) (*node.Node, error)

	// GetNodes gets a list of all registered nodes.
	GetNodes(context.Context) ([]*node.Node, error)

	// GetNodesForEntity gets a list of nodes registered to an entity ID.
	GetNodesForEntity(context.Context, signature.PublicKey) []*node.Node

	// WatchNodes returns a channel that produces a stream of
	// NodeEvent on node registration changes.
	WatchNodes() (<-chan *NodeEvent, *pubsub.Subscription)

	// WatchNodeList returns a channel that produces a stream of NodeList.
	// Upon subscription, the node list for the current epoch will be sent
	// immediately if available.
	//
	// Each node list will be sorted by node ID in lexographically ascending
	// order.
	WatchNodeList() (<-chan *NodeList, *pubsub.Subscription)

	// RegisterContract registers a contract.
	RegisterContract(context.Context, *contract.SignedContract) error

	// GetContract gets a contract by ID.
	GetContract(context.Context, signature.PublicKey) (*contract.Contract, error)

	// WatchContracts returns a stream of Contract.  Upon subscription,
	// all contracts will be sent immediately.
	WatchContracts() (<-chan *contract.Contract, *pubsub.Subscription)
}

// EntityEvent is the event that is returned via WatchEntities to signify
// entity registration changes and updates.
type EntityEvent struct {
	Entity         *entity.Entity
	IsRegistration bool
}

// NodeEvent is the event that is returned via WatchNodes to signify node
// registration changes and updates.
type NodeEvent struct {
	Node           *node.Node
	IsRegistration bool
}

// NodeList is a per-epoch immutable node list.
type NodeList struct {
	Epoch epochtime.EpochTime
	Nodes []*node.Node
}

// VerifyRegisterEntityArgs verifies arguments for RegisterEntity.
func VerifyRegisterEntityArgs(logger *logging.Logger, sigEnt *entity.SignedEntity) (*entity.Entity, error) {
	// XXX: Ensure ent is well-formed.
	var ent entity.Entity
	if sigEnt == nil {
		return nil, ErrInvalidArgument
	}
	if err := sigEnt.Open(RegisterEntitySignatureContext, &ent); err != nil {
		logger.Error("RegisterEntity: invalid signature",
			"signed_entity", sigEnt,
		)
		return nil, ErrInvalidSignature
	}
	if sigEnt.Signed.Signature.SanityCheck(ent.ID) != nil {
		logger.Error("RegisterEntity: invalid argument(s)",
			"signed_entity", sigEnt,
			"entity", ent,
		)
		return nil, ErrInvalidArgument
	}

	return &ent, nil
}

// VerifyDeregisterEntityArgs verifies arguments for DeregisterEntity.
func VerifyDeregisterEntityArgs(logger *logging.Logger, sigID *signature.SignedPublicKey) (signature.PublicKey, error) {
	var id signature.PublicKey
	if sigID == nil {
		return nil, ErrInvalidArgument
	}
	if err := sigID.Open(DeregisterEntitySignatureContext, &id); err != nil {
		logger.Error("DeregisterEntity: invalid signature",
			"signed_id", sigID,
		)
		return nil, ErrInvalidSignature
	}
	if sigID.Signed.Signature.SanityCheck(id) != nil {
		logger.Error("DeregisterEntity: invalid argument(s)",
			"entity_id", id,
			"signed_id", sigID,
		)
		return nil, ErrInvalidArgument
	}

	return id, nil
}

// VerifyRegisterNodeArgs verifies arguments for RegisterNode.
func VerifyRegisterNodeArgs(logger *logging.Logger, sigNode *node.SignedNode) (*node.Node, error) {
	// XXX: Ensure node is well-formed.
	var node node.Node
	if sigNode == nil {
		return nil, ErrInvalidArgument
	}
	if err := sigNode.Open(RegisterNodeSignatureContext, &node); err != nil {
		logger.Error("RegisterNode: invalid signature",
			"signed_node", sigNode,
		)
		return nil, ErrInvalidSignature
	}
	if sigNode.Signed.Signature.SanityCheck(node.EntityID) != nil {
		logger.Error("RegisterEntity: invalid argument(s)",
			"signed_node", sigNode,
			"node", node,
		)
		return nil, ErrInvalidArgument
	}

	return &node, nil
}

// VerifyRegisterContractArgs verifies arguments for RegisterContract.
func VerifyRegisterContractArgs(logger *logging.Logger, sigCon *contract.SignedContract) (*contract.Contract, error) {
	// XXX: Ensure contact is well-formed.
	var con contract.Contract
	if sigCon == nil {
		return nil, ErrInvalidArgument
	}
	if err := sigCon.Open(RegisterContractSignatureContext, &con); err != nil {
		logger.Error("RegisterContract: invalid signature",
			"signed_contract", sigCon,
		)
		return nil, ErrInvalidSignature
	}

	// TODO: Who should sign the contract? Current compute node assumes an entity (deployer).

	return &con, nil
}
