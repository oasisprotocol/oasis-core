package registry

import (
	"bytes"
	"sort"
	"sync"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime"
)

var _ EntityRegistry = (*MemoryEntityRegistry)(nil)

// MemoryEntityRegistry is a centralized in-memory EntityRegistry.
type MemoryEntityRegistry struct {
	logger *logging.Logger

	state memoryEntityRegistryState

	registrationNotifier *pubsub.Broker
	nodeNotifier         *pubsub.Broker
	nodeListNotifier     *pubsub.Broker

	lastEpoch epochtime.EpochTime
}

type memoryEntityRegistryState struct {
	sync.RWMutex

	entities map[registryMapID]*entity.Entity
	nodes    map[registryMapID]*node.Node
}

// RegisterEntity registers and or updates an entity with the registry.
//
// The signature should be made using RegisterEntitySignatureContext.
func (r *MemoryEntityRegistry) RegisterEntity(ent *entity.Entity, sig *signature.Signature) error {
	// XXX: Ensure ent is well-formed.
	if ent == nil || sig == nil || sig.SanityCheck(ent.ID) != nil {
		r.logger.Error("RegisterEntity: invalid argument(s)",
			"entity", ent,
			"signature", sig,
		)
		return ErrInvalidArgument
	}
	if !sig.Verify(RegisterEntitySignatureContext, ent.ToSignable()) {
		return ErrInvalidSignature
	}

	k := pubKeyToMapID(ent.ID)
	r.state.Lock()
	r.state.entities[k] = ent
	r.state.Unlock()

	r.logger.Debug("RegisterEntity: registered",
		"entity", ent,
	)

	r.registrationNotifier.Broadcast(&EntityEvent{
		Entity:         ent,
		IsRegistration: true,
	})

	return nil
}

// DeregisterEntity deregisters an entity.
//
// The signature should be made using DeregisterEntitySignatureContext.
func (r *MemoryEntityRegistry) DeregisterEntity(id signature.PublicKey, sig *signature.Signature) error {
	if sig == nil || sig.SanityCheck(id) != nil {
		r.logger.Error("DeregisterEntity: invalid argument(s)",
			"entity_id", id,
			"signature", sig,
		)
		return ErrInvalidArgument
	}
	if !sig.Verify(DeregisterEntitySignatureContext, id) {
		r.logger.Error("DeregisterEntity: invalid signature",
			"entity_id", id,
			"signature", sig,
		)
		return ErrInvalidSignature
	}

	var removedEntity *entity.Entity
	var removedNodes []*node.Node
	k := pubKeyToMapID(id)
	r.state.Lock()
	if removedEntity = r.state.entities[k]; removedEntity != nil {
		delete(r.state.entities, k)
		removedNodes = r.getNodesForEntryLocked(id)
		for _, v := range removedNodes {
			nk := pubKeyToMapID(v.ID)
			delete(r.state.nodes, nk)
		}
	}
	r.state.Unlock()

	r.logger.Debug("DeregisterEntity: complete",
		"entity_id", id,
		"removed_entity", removedEntity,
		"nodes_pruned", len(removedNodes),
	)

	if removedEntity != nil {
		r.registrationNotifier.Broadcast(&EntityEvent{
			Entity:         removedEntity,
			IsRegistration: false,
		})
		for _, v := range removedNodes {
			r.nodeNotifier.Broadcast(&NodeEvent{
				Node:           v,
				IsRegistration: false,
			})
		}
	}

	return nil
}

// GetEntity gets an entity by ID.
func (r *MemoryEntityRegistry) GetEntity(id signature.PublicKey) *entity.Entity {
	k := pubKeyToMapID(id)

	r.state.RLock()
	defer r.state.RUnlock()
	return r.state.entities[k]
}

// GetEntities gets a list of all registered entities.
func (r *MemoryEntityRegistry) GetEntities() []*entity.Entity {
	r.state.RLock()
	defer r.state.RUnlock()

	ret := make([]*entity.Entity, 0, len(r.state.entities))
	for _, v := range r.state.entities {
		ret = append(ret, v)
	}

	return ret
}

// WatchEntities returns a channel that produces a stream of
// EntityEvent on entity registration changes.
func (r *MemoryEntityRegistry) WatchEntities() (<-chan *EntityEvent, *pubsub.Subscription) {
	return subscribeTypedEntityEvent(r.registrationNotifier)
}

// RegisterNode registers and or updates a node with the registry.
//
// The signature should be made using RegisterNodeSignatureContext.
func (r *MemoryEntityRegistry) RegisterNode(node *node.Node, sig *signature.Signature) error {
	// XXX: Ensure node is well-formed.
	if node == nil || sig == nil || sig.SanityCheck(node.EntityID) != nil {
		r.logger.Error("RegisterNode: invalid argument(s)",
			"node", node,
			"signature", sig,
		)
		return ErrInvalidArgument
	}
	if !sig.Verify(RegisterNodeSignatureContext, node.ToSignable()) {
		return ErrInvalidSignature
	}

	k := pubKeyToMapID(node.ID)
	r.state.Lock()
	if r.state.entities[k] == nil {
		r.state.Unlock()
		r.logger.Error("RegisterNode: unknown entity in node registration",
			"node", node,
		)
		return ErrBadEntityForNode
	}
	r.state.nodes[k] = node
	r.state.Unlock()

	r.logger.Debug("RegisterNode: registered",
		"node", node,
	)

	r.nodeNotifier.Broadcast(&NodeEvent{
		Node:           node,
		IsRegistration: true,
	})

	return nil
}

// GetNode gets a node by ID.
func (r *MemoryEntityRegistry) GetNode(id signature.PublicKey) *node.Node {
	k := pubKeyToMapID(id)

	r.state.RLock()
	defer r.state.RUnlock()
	return r.state.nodes[k]
}

// GetNodes gets a list of all registered nodes.
func (r *MemoryEntityRegistry) GetNodes() []*node.Node {
	r.state.RLock()
	defer r.state.RUnlock()

	ret := make([]*node.Node, 0, len(r.state.nodes))
	for _, v := range r.state.nodes {
		ret = append(ret, v)
	}

	return ret
}

// GetNodesForEntity gets a list of nodes registered to an entity ID.
func (r *MemoryEntityRegistry) GetNodesForEntity(id signature.PublicKey) []*node.Node {
	r.state.RLock()
	defer r.state.RUnlock()

	return r.getNodesForEntryLocked(id)
}

// WatchNodes returns a channel that produces a stream of
// NodeEvent on node registration changes.
func (r *MemoryEntityRegistry) WatchNodes() (<-chan *NodeEvent, *pubsub.Subscription) {
	return subscribeTypedNodeEvent(r.nodeNotifier)
}

// WatchNodeList returns a channel that produces a stream of NodeList.
// Upon subscription, the node list for the current epoch will be sent
// immediately if available.
//
// Each node list will be sorted by node ID in lexographically ascending
// order.
func (r *MemoryEntityRegistry) WatchNodeList() (<-chan *NodeList, *pubsub.Subscription) {
	return subscribeTypedNodeList(r.nodeListNotifier)
}

func (r *MemoryEntityRegistry) getNodesForEntryLocked(id signature.PublicKey) []*node.Node {
	var ret []*node.Node

	// TODO/perf: This could be cached if it's a common operation.
	for _, v := range r.state.nodes {
		if id.Equal(v.EntityID) {
			ret = append(ret, v)
		}
	}

	return ret
}

func (r *MemoryEntityRegistry) worker(timeSource epochtime.TimeSource) {
	epochEvents, sub := timeSource.WatchEpochs()
	defer sub.Close()
	for {
		newEpoch, ok := <-epochEvents
		if !ok {
			r.logger.Debug("worker: terminating")
			return
		}

		r.logger.Debug("worker: epoch transition",
			"prev_epoch", r.lastEpoch,
			"epoch", newEpoch,
		)

		if newEpoch == r.lastEpoch {
			continue
		}

		// XXX: Sweep node list for expired nodes.
		r.buildNodeList(newEpoch)
		r.lastEpoch = newEpoch
	}
}

func (r *MemoryEntityRegistry) buildNodeList(newEpoch epochtime.EpochTime) {
	nodes := r.GetNodes()
	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i].ID, nodes[j].ID) == -1
	})

	r.logger.Debug("worker: built node list",
		"epoch", newEpoch,
		"nodes", nodes,
	)

	r.nodeListNotifier.Broadcast(&NodeList{
		Epoch: newEpoch,
		Nodes: nodes,
	})
}

// NewMemoryEntityRegistry constructs a new MemoryEntityRegistry instance.
func NewMemoryEntityRegistry(timeSource epochtime.TimeSource) EntityRegistry {
	r := &MemoryEntityRegistry{
		logger: logging.GetLogger("MemoryEntityRegistry"),
		state: memoryEntityRegistryState{
			entities: make(map[registryMapID]*entity.Entity),
			nodes:    make(map[registryMapID]*node.Node),
		},
		registrationNotifier: pubsub.NewBroker(false),
		nodeNotifier:         pubsub.NewBroker(false),
		nodeListNotifier:     pubsub.NewBroker(true),
		lastEpoch:            epochtime.EpochInvalid,
	}

	go r.worker(timeSource)

	return r
}
