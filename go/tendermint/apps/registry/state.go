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
	// SignedEntity map state key prefix.
	stateSignedEntityMap = "registry/signed_entity/%s"

	// SignedNode map state key prefix.
	stateSignedNodeMap = "registry/signed_node/%s"
	// SignedNode by entity map state key prefix.
	stateSignedNodeByEntityMap = "registry/signed_node_by_entity/%s/%s"

	// Runtime map state key prefix.
	stateSignedRuntimeMap = "registry/signed_runtime/%s"

	// KeyManagerOperator state key.
	stateKeyManagerOperator = "registry/km_operator"
)

var (
	// errEntityNotFound is the error returned when an entity is not found.
	errEntityNotFound = errors.New("registry state: entity not found")
	// errNodeNotFound is the error returned when node is not found.
	errNodeNotFound = errors.New("registry state: node not found")
)

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) getSignedEntityRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateSignedEntityMap, id.String())
}

func (s *immutableState) getEntity(id signature.PublicKey) (*entity.Entity, error) {
	signedEntityRaw, err := s.getSignedEntityRaw(id)
	if err != nil || signedEntityRaw == nil {
		return nil, errEntityNotFound
	}

	var signedEntity entity.SignedEntity
	if err = cbor.Unmarshal(signedEntityRaw, &signedEntity); err != nil {
		return nil, err
	}
	var entity entity.Entity
	if err = cbor.Unmarshal(signedEntity.Blob, &entity); err != nil {
		return nil, err
	}
	return &entity, nil
}

func (s *immutableState) getEntities() ([]*entity.Entity, error) {
	items, err := s.getAll(stateSignedEntityMap, &entity.SignedEntity{})
	if err != nil {
		return nil, err
	}

	var entities []*entity.Entity
	for _, item := range items {
		signedEntity := item.(*entity.SignedEntity)

		var entity entity.Entity
		if err = cbor.Unmarshal(signedEntity.Blob, &entity); err != nil {
			return nil, err
		}

		entities = append(entities, &entity)
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

func (s *immutableState) getSignedEntities() ([]*entity.SignedEntity, error) {
	items, err := s.getAll(stateSignedEntityMap, &entity.SignedEntity{})
	if err != nil {
		return nil, err
	}

	var entities []*entity.SignedEntity
	for _, item := range items {
		entity := item.(*entity.SignedEntity)
		entities = append(entities, entity)
	}

	return entities, nil
}

func (s *immutableState) getSignedNodeRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateSignedNodeMap, id.String())
}

func (s *immutableState) GetNode(id signature.PublicKey) (*node.Node, error) {
	signedNodeRaw, err := s.getSignedNodeRaw(id)
	if err != nil {
		return nil, err
	}
	if signedNodeRaw == nil {
		return nil, errNodeNotFound
	}
	signedNode := node.SignedNode{}
	err = cbor.Unmarshal(signedNodeRaw, &signedNode)
	if err != nil {
		return nil, err
	}
	node := node.Node{}
	err = cbor.Unmarshal(signedNode.Blob, &node)
	if err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *immutableState) GetNodes() ([]*node.Node, error) {
	items, err := s.getAll(stateSignedNodeMap, &node.SignedNode{})
	if err != nil {
		return nil, err
	}

	var nodes []*node.Node
	for _, item := range items {
		signedNode := item.(*node.SignedNode)

		var node node.Node
		if err = cbor.Unmarshal(signedNode.Blob, &node); err != nil {
			return nil, err
		}

		nodes = append(nodes, &node)
	}

	return nodes, nil
}

func (s *immutableState) getNodesRaw() ([]byte, error) {
	nodes, err := s.GetNodes()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(nodes), nil
}

func (s *immutableState) getSignedNodes() ([]*node.SignedNode, error) {
	items, err := s.getAll(stateSignedNodeMap, &node.SignedNode{})
	if err != nil {
		return nil, err
	}

	var nodes []*node.SignedNode
	for _, item := range items {
		node := item.(*node.SignedNode)
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// GetRuntime looks up a runtime by its identifier and returns it.
func (s *immutableState) GetRuntime(id signature.PublicKey) (*registry.Runtime, error) {
	raw, err := s.getSignedRuntimeRaw(id)
	if err != nil {
		return nil, err
	}

	var signedRuntime registry.SignedRuntime
	if err = cbor.Unmarshal(raw, &signedRuntime); err != nil {
		return nil, err
	}
	var runtime registry.Runtime
	if err = cbor.Unmarshal(signedRuntime.Blob, &runtime); err != nil {
		return nil, err
	}
	return &runtime, err
}

func (s *immutableState) getSignedRuntimeRaw(id signature.PublicKey) ([]byte, error) {
	return s.getByID(stateSignedRuntimeMap, id.String())
}

// GetRuntimes returns a list of all registered runtimes.
func (s *immutableState) GetRuntimes() ([]*registry.Runtime, error) {
	items, err := s.getAll(stateSignedRuntimeMap, &registry.SignedRuntime{})
	if err != nil {
		return nil, err
	}

	var runtimes []*registry.Runtime
	for _, item := range items {
		signedRuntime := item.(*registry.SignedRuntime)

		var rt registry.Runtime
		if err = cbor.Unmarshal(signedRuntime.Blob, &rt); err != nil {
			return nil, err
		}

		runtimes = append(runtimes, &rt)
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

func (s *immutableState) getSignedRuntimes() ([]*registry.SignedRuntime, error) {
	items, err := s.getAll(stateSignedRuntimeMap, &registry.SignedRuntime{})
	if err != nil {
		return nil, err
	}

	var runtimes []*registry.SignedRuntime
	for _, item := range items {
		rt := item.(*registry.SignedRuntime)
		runtimes = append(runtimes, rt)
	}

	return runtimes, nil
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

func (s *immutableState) getKeyManagerOperator() signature.PublicKey {
	_, value := s.Snapshot.Get([]byte(stateKeyManagerOperator))
	if value == nil {
		return nil
	}

	var id signature.PublicKey
	if err := id.UnmarshalBinary(value); err != nil {
		panic("tendermint/registry: corrupted key manager operator: " + err.Error())
	}

	return id
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

func (s *MutableState) createEntity(ent *entity.Entity, sigEnt *entity.SignedEntity) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateSignedEntityMap, ent.ID.String())),
		sigEnt.MarshalCBOR(),
	)
}

func (s *MutableState) removeEntity(id signature.PublicKey) (entity.Entity, []node.Node) {
	var removedSignedEntity entity.SignedEntity
	var removedEntity entity.Entity
	var removedNodes []node.Node
	data, removed := s.tree.Remove([]byte(fmt.Sprintf(stateSignedEntityMap, id.String())))
	if removed {
		// Remove any associated nodes.
		s.tree.IterateRangeInclusive(
			[]byte(fmt.Sprintf(stateSignedNodeByEntityMap, id.String(), "")),
			[]byte(fmt.Sprintf(stateSignedNodeByEntityMap, id.String(), abci.LastID)),
			true,
			func(key, value []byte, version int64) bool {
				// Remove all dependent nodes.
				nodeData, _ := s.tree.Remove([]byte(fmt.Sprintf(stateSignedNodeMap, value)))
				s.tree.Remove([]byte(fmt.Sprintf(stateSignedNodeByEntityMap, id.String(), value)))

				var removedSignedNode node.SignedNode
				var removedNode node.Node
				cbor.MustUnmarshal(nodeData, &removedSignedNode)
				cbor.MustUnmarshal(removedSignedNode.Blob, &removedNode)

				removedNodes = append(removedNodes, removedNode)
				return false
			},
		)

		cbor.MustUnmarshal(data, &removedSignedEntity)
		cbor.MustUnmarshal(removedSignedEntity.Blob, &removedEntity)
	}

	return removedEntity, removedNodes
}

func (s *MutableState) createNode(node *node.Node, signedNode *node.SignedNode) error {
	// Ensure that the entity exists.
	ent, err := s.getSignedEntityRaw(node.EntityID)
	if ent == nil || err != nil {
		return errEntityNotFound
	}

	s.tree.Set(
		[]byte(fmt.Sprintf(stateSignedNodeMap, node.ID.String())),
		signedNode.MarshalCBOR(),
	)

	s.tree.Set(
		[]byte(fmt.Sprintf(stateSignedNodeByEntityMap, node.EntityID.String(), node.ID.String())),
		[]byte(node.ID.String()),
	)

	return nil
}

func (s *MutableState) removeNode(node *node.Node) {
	s.tree.Remove([]byte(fmt.Sprintf(stateSignedNodeMap, node.ID.String())))
	s.tree.Remove([]byte(fmt.Sprintf(stateSignedNodeByEntityMap, node.EntityID.String(), node.ID.String())))
}

func (s *MutableState) createRuntime(rt *registry.Runtime, sigRt *registry.SignedRuntime) error {
	entID := sigRt.Signature.PublicKey
	ent, err := s.getSignedEntityRaw(entID)
	if ent == nil || err != nil {
		return errEntityNotFound
	}

	s.tree.Set(
		[]byte(fmt.Sprintf(stateSignedRuntimeMap, rt.ID.String())),
		sigRt.MarshalCBOR(),
	)

	return nil
}

func (s *MutableState) setKeyManagerOperator(id signature.PublicKey) {
	if len(id) == 0 {
		return
	}

	value, _ := id.MarshalBinary()
	s.tree.Set([]byte(stateKeyManagerOperator), value)
}

// NewMutableState creates a new mutable registry state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
