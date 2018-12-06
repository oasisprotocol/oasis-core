package registry

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const (
	// Entity map state key prefix.
	stateEntityMap = "registry/entity/%s"

	// Node map state key prefix.
	stateNodeMap = "registry/node/%s"
	// Node by entity map state key prefix.
	stateNodeByEntityMap = "registry/node_by_entity/%s/%s"

	// Runtime map state key prefix.
	stateRuntimeMap = "registry/runtime/%s"

	// Highest hex-encoded node/entity/runtime identifier.
	// TODO: Should we move this to common?
	lastID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

var (
	// errEntityNotFound is the error returned when an entity is not found.
	errEntityNotFound = errors.New("registry state: entity not found")
)

// ImmutableState is an immutable registry state wrapper.
type ImmutableState struct {
	snapshot *iavl.ImmutableTree
}

// NewImmutableState creates a new immutable registry state wrapper.
func NewImmutableState(state *abci.ApplicationState, version int64) (*ImmutableState, error) {
	if version <= 0 || version > state.BlockHeight() {
		version = state.BlockHeight()
	}

	snapshot, err := state.DeliverTxTree().GetImmutable(version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{snapshot: snapshot}, nil
}

// GetEntityRaw looks up an entity by its identifier and returns its serialized form.
func (s *ImmutableState) GetEntityRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateEntityMap, id.String())
}

// GetEntity looks up an entity by its identifier and returns it.
func (s *ImmutableState) GetEntity(id signature.PublicKey) (*entity.Entity, error) {
	raw, err := s.GetEntityRaw(id)
	if err != nil {
		return nil, err
	}

	var ent entity.Entity
	err = ent.UnmarshalCBOR(raw)
	return &ent, err
}

// GetEntitiesRaw returns a marshalled list of all registered entities.
func (s *ImmutableState) GetEntitiesRaw() ([]byte, error) {
	entities, err := s.GetEntities()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(entities), nil
}

// GetEntities returns a list of all registered entities.
func (s *ImmutableState) GetEntities() ([]*entity.Entity, error) {
	items, err := s.getAll(stateEntityMap, &entity.Entity{})
	if err != nil {
		return nil, err
	}

	var entities []*entity.Entity
	for _, item := range items {
		entity := item.(*entity.Entity)
		entities = append(entities, entity)
	}

	return entities, nil
}

// GetNodeRaw looks up a node by its identifier and returns its serialized form.
func (s *ImmutableState) GetNodeRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateNodeMap, id.String())
}

// GetNode looks up a node by its identifier and returns it.
func (s *ImmutableState) GetNode(id signature.PublicKey) (*node.Node, error) {
	raw, err := s.GetNodeRaw(id)
	if err != nil {
		return nil, err
	}

	var node node.Node
	err = node.UnmarshalCBOR(raw)
	return &node, err
}

// GetNodesRaw returns a marshalled list of all registered nodes.
func (s *ImmutableState) GetNodesRaw() ([]byte, error) {
	nodes, err := s.GetNodes()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(nodes), nil
}

// GetNodes returns a list of all registered nodes.
func (s *ImmutableState) GetNodes() ([]*node.Node, error) {
	items, err := s.getAll(stateNodeMap, &node.Node{})
	if err != nil {
		return nil, err
	}

	var nodes []*node.Node
	for _, item := range items {
		node := item.(*node.Node)
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// GetRuntimeRaw looks up a runtime by its identifier and returns its serialized form.
func (s *ImmutableState) GetRuntimeRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateRuntimeMap, id.String())
}

// GetRuntime looks up a runtime by its identifier and returns it.
func (s *ImmutableState) GetRuntime(id signature.PublicKey) (*registry.Runtime, error) {
	raw, err := s.GetRuntimeRaw(id)
	if err != nil {
		return nil, err
	}

	var con registry.Runtime
	err = con.UnmarshalCBOR(raw)
	return &con, err
}

// GetRuntimesRaw returns a marshalled list of all registered runtimes.
func (s *ImmutableState) GetRuntimesRaw() ([]byte, error) {
	runtimes, err := s.GetRuntimes()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(runtimes), nil
}

// GetRuntimes returns a list of all registered runtimes.
func (s *ImmutableState) GetRuntimes() ([]*registry.Runtime, error) {
	items, err := s.getAll(stateRuntimeMap, &registry.Runtime{})
	if err != nil {
		return nil, err
	}

	var runtimes []*registry.Runtime
	for _, item := range items {
		runtime := item.(*registry.Runtime)
		runtimes = append(runtimes, runtime)
	}

	return runtimes, nil
}

func (s *ImmutableState) getAll(
	stateKey string,
	item common.Cloneable,
) ([]interface{}, error) {
	var items []interface{}
	s.snapshot.IterateRangeInclusive(
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

	return items, nil
}

func (s *ImmutableState) getByID(stateKey string, id string) ([]byte, error) {
	_, value := s.snapshot.Get([]byte(fmt.Sprintf(stateKey, id)))

	return value, nil
}

// MutableState is a mutable registry state wrapper.
type MutableState struct {
	ImmutableState

	tree *iavl.MutableTree
}

// NewMutableState creates a new mutable registry state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	return &MutableState{
		ImmutableState: ImmutableState{snapshot: tree.ImmutableTree},
		tree:           tree,
	}
}

// CreateEntity creates a new entity.
func (s *MutableState) CreateEntity(ent *entity.Entity) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateEntityMap, ent.ID.String())),
		ent.MarshalCBOR(),
	)
}

// RemoveEntity removes an entity and all associated nodes.
//
// Returns the removed entity and a list of removed nodes.
func (s *MutableState) RemoveEntity(id signature.PublicKey) (entity.Entity, []node.Node) {
	var removedEntity entity.Entity
	var removedNodes []node.Node
	data, removed := s.tree.Remove([]byte(fmt.Sprintf(stateEntityMap, id.String())))
	if removed {
		// Remove any associated nodes.
		s.tree.IterateRangeInclusive(
			[]byte(fmt.Sprintf(stateNodeByEntityMap, id.String(), "")),
			[]byte(fmt.Sprintf(stateNodeByEntityMap, id.String(), lastID)),
			true,
			func(key, value []byte, version int64) bool {
				// Remove all dependent nodes.
				nodeData, _ := s.tree.Remove([]byte(fmt.Sprintf(stateNodeMap, value)))
				s.tree.Remove([]byte(fmt.Sprintf(stateNodeByEntityMap, id.String(), value)))

				var removedNode node.Node
				cbor.MustUnmarshal(nodeData, &removedNode)

				removedNodes = append(removedNodes, removedNode)
				return false
			},
		)

		cbor.MustUnmarshal(data, &removedEntity)
	}

	return removedEntity, removedNodes
}

// CreateNode creates a new node.
func (s *MutableState) CreateNode(node *node.Node) error {
	// Ensure that the entity exists.
	ent, err := s.GetEntityRaw(node.EntityID)
	if ent == nil || err != nil {
		return errEntityNotFound
	}

	s.tree.Set(
		[]byte(fmt.Sprintf(stateNodeMap, node.ID.String())),
		node.MarshalCBOR(),
	)

	s.tree.Set(
		[]byte(fmt.Sprintf(stateNodeByEntityMap, node.EntityID.String(), node.ID.String())),
		[]byte(node.ID.String()),
	)

	return nil
}

// RemoveNode removes a node.
func (s *MutableState) RemoveNode(node *node.Node) {
	s.tree.Remove([]byte(fmt.Sprintf(stateNodeMap, node.ID.String())))
	s.tree.Remove([]byte(fmt.Sprintf(stateNodeByEntityMap, node.EntityID.String(), node.ID.String())))
}

// CreateRuntime creates a new runtime.
func (s *MutableState) CreateRuntime(con *registry.Runtime) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateRuntimeMap, con.ID.String())),
		con.MarshalCBOR(),
	)
}
