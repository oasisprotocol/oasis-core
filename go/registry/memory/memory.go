// Package memory implements the memory backed registry backend.
package memory

import (
	"bytes"
	"sort"
	"sync"

	"github.com/eapache/channels"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/registry/api"
)

// BackendName is the name of this implementation.
const BackendName = "memory"

var _ api.Backend = (*memoryBackend)(nil)

type memoryBackend struct {
	logger *logging.Logger

	state memoryBackendState

	entityNotifier   *pubsub.Broker
	nodeNotifier     *pubsub.Broker
	nodeListNotifier *pubsub.Broker
	contractNotifier *pubsub.Broker

	lastEpoch epochtime.EpochTime
}

type memoryBackendState struct {
	sync.RWMutex

	entities  map[signature.MapKey]*entity.Entity
	nodes     map[signature.MapKey]*node.Node
	contracts map[signature.MapKey]*contract.Contract
}

func (r *memoryBackend) RegisterEntity(ctx context.Context, ent *entity.Entity, sig *signature.Signature) error {
	// XXX: Ensure ent is well-formed.
	if ent == nil || sig == nil || sig.SanityCheck(ent.ID) != nil {
		r.logger.Error("RegisterEntity: invalid argument(s)",
			"entity", ent,
			"signature", sig,
		)
		return api.ErrInvalidArgument
	}
	if !sig.Verify(api.RegisterEntitySignatureContext, ent.ToSignable()) {
		return api.ErrInvalidSignature
	}

	r.state.Lock()
	r.state.entities[ent.ID.ToMapKey()] = ent
	r.state.Unlock()

	r.logger.Debug("RegisterEntity: registered",
		"entity", ent,
	)

	r.entityNotifier.Broadcast(&api.EntityEvent{
		Entity:         ent,
		IsRegistration: true,
	})

	return nil
}

func (r *memoryBackend) DeregisterEntity(ctx context.Context, id signature.PublicKey, sig *signature.Signature) error {
	if sig == nil || sig.SanityCheck(id) != nil {
		r.logger.Error("DeregisterEntity: invalid argument(s)",
			"entity_id", id,
			"signature", sig,
		)
		return api.ErrInvalidArgument
	}
	if !sig.Verify(api.DeregisterEntitySignatureContext, id) {
		r.logger.Error("DeregisterEntity: invalid signature",
			"entity_id", id,
			"signature", sig,
		)
		return api.ErrInvalidSignature
	}

	var removedEntity *entity.Entity
	var removedNodes []*node.Node
	mk := id.ToMapKey()
	r.state.Lock()
	if removedEntity = r.state.entities[mk]; removedEntity != nil {
		delete(r.state.entities, mk)
		removedNodes = r.getNodesForEntryLocked(id)
		for _, v := range removedNodes {
			delete(r.state.nodes, v.ID.ToMapKey())
		}
	}
	r.state.Unlock()

	r.logger.Debug("DeregisterEntity: complete",
		"entity_id", id,
		"removed_entity", removedEntity,
		"nodes_pruned", len(removedNodes),
	)

	if removedEntity != nil {
		r.entityNotifier.Broadcast(&api.EntityEvent{
			Entity:         removedEntity,
			IsRegistration: false,
		})
		for _, v := range removedNodes {
			r.nodeNotifier.Broadcast(&api.NodeEvent{
				Node:           v,
				IsRegistration: false,
			})
		}
	}

	return nil
}

func (r *memoryBackend) GetEntity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	r.state.RLock()
	defer r.state.RUnlock()

	ent := r.state.entities[id.ToMapKey()]
	if ent == nil {
		return nil, api.ErrNoSuchEntity
	}

	return ent, nil
}

func (r *memoryBackend) GetEntities(ctx context.Context) ([]*entity.Entity, error) {
	r.state.RLock()
	defer r.state.RUnlock()

	ret := make([]*entity.Entity, 0, len(r.state.entities))
	for _, v := range r.state.entities {
		ret = append(ret, v)
	}

	return ret, nil
}

func (r *memoryBackend) WatchEntities() (<-chan *api.EntityEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.EntityEvent)
	sub := r.entityNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (r *memoryBackend) RegisterNode(ctx context.Context, node *node.Node, sig *signature.Signature) error {
	// XXX: Ensure node is well-formed.
	if node == nil || sig == nil || sig.SanityCheck(node.EntityID) != nil {
		r.logger.Error("RegisterNode: invalid argument(s)",
			"node", node,
			"signature", sig,
		)
		return api.ErrInvalidArgument
	}
	if !sig.Verify(api.RegisterNodeSignatureContext, node.ToSignable()) {
		return api.ErrInvalidSignature
	}

	mk := node.ID.ToMapKey()
	r.state.Lock()
	if r.state.entities[mk] == nil {
		r.state.Unlock()
		r.logger.Error("RegisterNode: unknown entity in node registration",
			"node", node,
		)
		return api.ErrBadEntityForNode
	}
	r.state.nodes[mk] = node
	r.state.Unlock()

	r.logger.Debug("RegisterNode: registered",
		"node", node,
	)

	r.nodeNotifier.Broadcast(&api.NodeEvent{
		Node:           node,
		IsRegistration: true,
	})

	return nil
}

func (r *memoryBackend) GetNode(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	r.state.RLock()
	defer r.state.RUnlock()

	node := r.state.nodes[id.ToMapKey()]
	if node == nil {
		return nil, api.ErrNoSuchNode
	}

	return node, nil
}

func (r *memoryBackend) GetNodes(ctx context.Context) ([]*node.Node, error) {
	r.state.RLock()
	defer r.state.RUnlock()

	ret := make([]*node.Node, 0, len(r.state.nodes))
	for _, v := range r.state.nodes {
		ret = append(ret, v)
	}

	return ret, nil
}

func (r *memoryBackend) GetNodesForEntity(ctx context.Context, id signature.PublicKey) []*node.Node {
	r.state.RLock()
	defer r.state.RUnlock()

	return r.getNodesForEntryLocked(id)
}

func (r *memoryBackend) WatchNodes() (<-chan *api.NodeEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.NodeEvent)
	sub := r.nodeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (r *memoryBackend) WatchNodeList() (<-chan *api.NodeList, *pubsub.Subscription) {
	typedCh := make(chan *api.NodeList)
	sub := r.nodeListNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (r *memoryBackend) getNodesForEntryLocked(id signature.PublicKey) []*node.Node {
	var ret []*node.Node

	// TODO/perf: This could be cached if it's a common operation.
	for _, v := range r.state.nodes {
		if id.Equal(v.EntityID) {
			ret = append(ret, v)
		}
	}

	return ret
}

func (r *memoryBackend) worker(timeSource epochtime.Backend) {
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

func (r *memoryBackend) buildNodeList(newEpoch epochtime.EpochTime) {
	nodes, err := r.GetNodes(context.Background())
	if err != nil {
		panic(err)
	}

	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i].ID, nodes[j].ID) == -1
	})

	r.logger.Debug("worker: built node list",
		"epoch", newEpoch,
		"nodes", nodes,
	)

	r.nodeListNotifier.Broadcast(&api.NodeList{
		Epoch: newEpoch,
		Nodes: nodes,
	})
}

func (r *memoryBackend) RegisterContract(ctx context.Context, con *contract.Contract, sig *signature.Signature) error {
	// XXX: Ensure contact is well-formed.
	if con == nil || sig == nil || sig.SanityCheck(con.ID) != nil {
		r.logger.Error("RegisterContract: invalid argument(s)",
			"contract", con,
			"signature", sig,
		)
		return api.ErrInvalidArgument
	}
	if !sig.Verify(api.RegisterContractSignatureContext, con.ToSignable()) {
		return api.ErrInvalidSignature
	}

	r.state.Lock()
	// XXX: Should this reject attempts to alter an existing registration?
	r.state.contracts[con.ID.ToMapKey()] = con
	r.state.Unlock()

	r.logger.Debug("RegisterContract: registered",
		"contract", con,
	)

	r.contractNotifier.Broadcast(con)

	return nil
}

func (r *memoryBackend) GetContract(ctx context.Context, id signature.PublicKey) (*contract.Contract, error) {
	r.state.RLock()
	defer r.state.RUnlock()

	con := r.state.contracts[id.ToMapKey()]
	if con == nil {
		return nil, api.ErrNoSuchContract
	}

	return con, nil
}

func (r *memoryBackend) WatchContracts() (<-chan *contract.Contract, *pubsub.Subscription) {
	typedCh := make(chan *contract.Contract)
	sub := r.contractNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

// New constructs a new memory backed registry Backend instance.
func New(timeSource epochtime.Backend) api.Backend {
	r := &memoryBackend{
		logger: logging.GetLogger("registry/memory"),
		state: memoryBackendState{
			entities:  make(map[signature.MapKey]*entity.Entity),
			nodes:     make(map[signature.MapKey]*node.Node),
			contracts: make(map[signature.MapKey]*contract.Contract),
		},
		entityNotifier:   pubsub.NewBroker(false),
		nodeNotifier:     pubsub.NewBroker(false),
		nodeListNotifier: pubsub.NewBroker(true),
		lastEpoch:        epochtime.EpochInvalid,
	}
	r.contractNotifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		wr := ch.In()

		r.state.RLock()
		defer r.state.RUnlock()
		for _, v := range r.state.contracts {
			wr <- v
		}
	})

	go r.worker(timeSource)

	return r
}
