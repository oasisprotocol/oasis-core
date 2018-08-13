// Package api implements the runtime and entity registry APIs.
package api

import (
	"errors"

	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
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
	RegisterEntity(context.Context, *entity.Entity, *signature.Signature) error

	// DeregisterEntity deregisters an entity.
	//
	// The signature should be made using DeregisterEntitySignatureContext.
	DeregisterEntity(context.Context, signature.PublicKey, *signature.Signature) error

	// GetEntity gets an entity by ID.
	GetEntity(context.Context, signature.PublicKey) (*entity.Entity, error)

	// GetEntities gets a list of all registered entities.
	GetEntities(context.Context) []*entity.Entity

	// WatchEntities returns a channel that produces a stream of
	// EntityEvent on entity registration changes.
	WatchEntities() (<-chan *EntityEvent, *pubsub.Subscription)

	// RegisterNode registers and or updates a node with the registry.
	//
	// The signature should be made using RegisterNodeSignatureContext.
	RegisterNode(context.Context, *node.Node, *signature.Signature) error

	// GetNode gets a node by ID.
	GetNode(context.Context, signature.PublicKey) (*node.Node, error)

	// GetNodes gets a list of all registered nodes.
	GetNodes(context.Context) []*node.Node

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
	RegisterContract(context.Context, *contract.Contract, *signature.Signature) error

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
