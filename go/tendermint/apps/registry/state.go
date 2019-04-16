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
)

var (
	// errEntityNotFound is the error returned when an entity is not found.
	errEntityNotFound = errors.New("registry state: entity not found")
)

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) getEntityRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateEntityMap, id.String())
}

func (s *immutableState) getEntities() ([]*entity.Entity, error) {
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

func (s *immutableState) getEntitiesRaw() ([]byte, error) {
	entities, err := s.getEntities()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(entities), nil
}

func (s *immutableState) getNodeRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateNodeMap, id.String())
}

func (s *immutableState) GetNode(id signature.PublicKey) (*node.Node, error) {
	nodeRaw, err := s.getNodeRaw(id)
	if err != nil {
		return nil, err
	}
	node := node.Node{}
	err = cbor.Unmarshal(nodeRaw, &node)
	if err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *immutableState) getNodes() ([]*node.Node, error) {
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

func (s *immutableState) getNodesRaw() ([]byte, error) {
	nodes, err := s.getNodes()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(nodes), nil
}

// GetRuntime looks up a runtime by its identifier and returns it.
func (s *immutableState) GetRuntime(id signature.PublicKey) (*registry.Runtime, error) {
	raw, err := s.getRuntimeRaw(id)
	if err != nil {
		return nil, err
	}

	var con registry.Runtime
	err = con.UnmarshalCBOR(raw)
	return &con, err
}

func (s *immutableState) getRuntimeRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateRuntimeMap, id.String())
}

// GetRuntimes returns a list of all registered runtimes.
func (s *immutableState) GetRuntimes() ([]*registry.Runtime, error) {
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

func (s *immutableState) getRuntimesRaw() ([]byte, error) {
	runtimes, err := s.GetRuntimes()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(runtimes), nil
}

func (s *immutableState) getAll(
	stateKey string,
	item common.Cloneable,
) ([]interface{}, error) {
	var items []interface{}
	s.Snapshot.IterateRangeInclusive(
		[]byte(fmt.Sprintf(stateKey, "")),
		[]byte(fmt.Sprintf(stateKey, abci.LastID)),
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

func (s *immutableState) getByID(stateKey string, id string) ([]byte, error) {
	_, value := s.Snapshot.Get([]byte(fmt.Sprintf(stateKey, id)))

	return value, nil
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{inner}, nil
}

// MutableState is a mutable registry state wrapper.
type MutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (s *MutableState) createEntity(ent *entity.Entity) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateEntityMap, ent.ID.String())),
		ent.MarshalCBOR(),
	)
}

func (s *MutableState) removeEntity(id signature.PublicKey) (entity.Entity, []node.Node) {
	var removedEntity entity.Entity
	var removedNodes []node.Node
	data, removed := s.tree.Remove([]byte(fmt.Sprintf(stateEntityMap, id.String())))
	if removed {
		// Remove any associated nodes.
		s.tree.IterateRangeInclusive(
			[]byte(fmt.Sprintf(stateNodeByEntityMap, id.String(), "")),
			[]byte(fmt.Sprintf(stateNodeByEntityMap, id.String(), abci.LastID)),
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

func (s *MutableState) createNode(node *node.Node) error {
	// Ensure that the entity exists.
	ent, err := s.getEntityRaw(node.EntityID)
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

func (s *MutableState) removeNode(node *node.Node) {
	s.tree.Remove([]byte(fmt.Sprintf(stateNodeMap, node.ID.String())))
	s.tree.Remove([]byte(fmt.Sprintf(stateNodeByEntityMap, node.EntityID.String(), node.ID.String())))
}

func (s *MutableState) createRuntime(con *registry.Runtime, entID signature.PublicKey) error {
	ent, err := s.getEntityRaw(entID)
	if ent == nil || err != nil {
		return errEntityNotFound
	}

	s.tree.Set(
		[]byte(fmt.Sprintf(stateRuntimeMap, con.ID.String())),
		con.MarshalCBOR(),
	)

	return nil
}

// NewMutableState creates a new mutable registry state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
