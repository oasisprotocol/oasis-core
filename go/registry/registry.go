// Package registry implements the runtime and entity registries.
package registry

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime"
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

	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New("registry: invalid argument")

	// ErrInvalidSignature is the error returned on an invalid signature.
	ErrInvalidSignature = errors.New("registry: invalid signature")

	// ErrBadEntityForNode is the error returned when a node registration
	// with an unknown entity is attempted.
	ErrBadEntityForNode = errors.New("registry: unknown entity in node registration")
)

// EntityRegistry is a entity registry implementation.
type EntityRegistry interface {
	// RegisterEntity registers and or updates an entity with the registry.
	//
	// The signature should be made using RegisterEntitySignatureContext.
	RegisterEntity(*entity.Entity, *signature.Signature) error

	// DeregisterEntity deregisters an entity.
	//
	// The signature should be made using DeregisterEntitySignatureContext.
	DeregisterEntity(signature.PublicKey, *signature.Signature) error

	// GetEntity gets an entity by ID.
	GetEntity(signature.PublicKey) *entity.Entity

	// GetEntities gets a list of all registered entities.
	GetEntities() []*entity.Entity

	// WatchEntities returns a channel that produces a stream of
	// EntityEvent on entity registration changes.
	WatchEntities() <-chan *EntityEvent

	// RegisterNode registers and or updates a node with the registry.
	//
	// The signature should be made using RegisterNodeSignatureContext.
	RegisterNode(*node.Node, *signature.Signature) error

	// GetNode gets a node by ID.
	GetNode(signature.PublicKey) *node.Node

	// GetNodes gets a list of all registered nodes.
	GetNodes() []*node.Node

	// GetNodesForEntity gets a list of nodes registered to an entity ID.
	GetNodesForEntity(signature.PublicKey) []*node.Node

	// WatchNodes returns a channel that produces a stream of
	// NodeEvent on node registration changes.
	WatchNodes() <-chan *NodeEvent

	// WatchNodeList returns a channel that produces a stream of NodeList.
	// Upon subscription, the node list for the current epoch will be sent
	// immediately if available.
	//
	// Each node list will be sorted by node ID in lexographically ascending
	// order.
	WatchNodeList() <-chan *NodeList
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

type registryMapID [signature.PublicKeySize]byte

func pubKeyToMapID(id signature.PublicKey) registryMapID {
	if len(id) != signature.PublicKeySize {
		panic("registry: invalid ID")
	}

	var ret registryMapID
	copy(ret[:], id)

	return ret
}

func subscribeTypedEntityEvent(notifier *pubsub.Broker) <-chan *EntityEvent {
	rawCh := notifier.Subscribe()
	typedCh := make(chan *EntityEvent)

	go func() {
		for {
			ev, ok := <-rawCh
			if !ok {
				close(typedCh)
				return
			}
			typedCh <- ev.(*EntityEvent)
		}
	}()

	return typedCh
}

func subscribeTypedNodeEvent(notifier *pubsub.Broker) <-chan *NodeEvent {
	rawCh := notifier.Subscribe()
	typedCh := make(chan *NodeEvent)

	go func() {
		for {
			ev, ok := <-rawCh
			if !ok {
				close(typedCh)
				return
			}
			typedCh <- ev.(*NodeEvent)
		}
	}()

	return typedCh
}

func subscribeTypedNodeList(notifier *pubsub.Broker) <-chan *NodeList {
	rawCh := notifier.Subscribe()
	typedCh := make(chan *NodeList)

	go func() {
		for {
			l, ok := <-rawCh
			if !ok {
				close(typedCh)
				return
			}
			typedCh <- l.(*NodeList)
		}
	}()

	return typedCh

}
