package registry

import (
	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/keyformat"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

var (
	// signedEntityKeyFmt is the key format used for signed entities.
	//
	// Value is CBOR-serialized signed entity.
	signedEntityKeyFmt = keyformat.New(0x10, &signature.MapKey{})
	// signedNodeKeyFmt is the key format used for signed nodes.
	//
	// Value is CBOR-serialized signed node.
	signedNodeKeyFmt = keyformat.New(0x11, &signature.MapKey{})
	// signedNodeByEntityKeyFmt is the key format used for signed node by entity
	// index.
	//
	// Value is empty.
	signedNodeByEntityKeyFmt = keyformat.New(0x12, &signature.MapKey{}, &signature.MapKey{})
	// signedRuntimeKeyFmt is the key format used for signed runtimes.
	//
	// Value is CBOR-serialized signed runtime.
	signedRuntimeKeyFmt = keyformat.New(0x13, &signature.MapKey{})
	// keyManagerOperatorKeyFmt is the key format used for the key manager
	// operator.
	//
	// Value is key manager operator public key.
	keyManagerOperatorKeyFmt = keyformat.New(0x14)

	// errEntityNotFound is the error returned when an entity is not found.
	errEntityNotFound = errors.New("registry state: entity not found")
	// errNodeNotFound is the error returned when node is not found.
	errNodeNotFound = errors.New("registry state: node not found")
)

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) getSignedEntityRaw(id signature.PublicKey) ([]byte, error) {
	_, value := s.Snapshot.Get(signedEntityKeyFmt.Encode(&id))
	return value, nil
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
	var entities []*entity.Entity
	s.Snapshot.IterateRange(
		signedEntityKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !signedEntityKeyFmt.Decode(key) {
				return true
			}

			var signedEntity entity.SignedEntity
			if err := cbor.Unmarshal(value, &signedEntity); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}
			var entity entity.Entity
			if err := cbor.Unmarshal(signedEntity.Blob, &entity); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			entities = append(entities, &entity)

			return false
		},
	)

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
	var entities []*entity.SignedEntity
	s.Snapshot.IterateRange(
		signedEntityKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !signedEntityKeyFmt.Decode(key) {
				return true
			}

			var signedEntity entity.SignedEntity
			if err := cbor.Unmarshal(value, &signedEntity); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			entities = append(entities, &signedEntity)

			return false
		},
	)

	return entities, nil
}

func (s *immutableState) getSignedNodeRaw(id signature.PublicKey) ([]byte, error) {
	_, value := s.Snapshot.Get(signedNodeKeyFmt.Encode(&id))
	return value, nil
}

func (s *immutableState) GetNode(id signature.PublicKey) (*node.Node, error) {
	signedNodeRaw, err := s.getSignedNodeRaw(id)
	if err != nil {
		return nil, err
	}
	if signedNodeRaw == nil {
		return nil, errNodeNotFound
	}

	var signedNode node.SignedNode
	if err = cbor.Unmarshal(signedNodeRaw, &signedNode); err != nil {
		return nil, err
	}
	var node node.Node
	if err = cbor.Unmarshal(signedNode.Blob, &node); err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *immutableState) GetNodes() ([]*node.Node, error) {
	var nodes []*node.Node
	s.Snapshot.IterateRange(
		signedNodeKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !signedNodeKeyFmt.Decode(key) {
				return true
			}

			var signedNode node.SignedNode
			if err := cbor.Unmarshal(value, &signedNode); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}
			var node node.Node
			if err := cbor.Unmarshal(signedNode.Blob, &node); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			nodes = append(nodes, &node)

			return false
		},
	)

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
	var nodes []*node.SignedNode
	s.Snapshot.IterateRange(
		signedNodeKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !signedNodeKeyFmt.Decode(key) {
				return true
			}

			var signedNode node.SignedNode
			if err := cbor.Unmarshal(value, &signedNode); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			nodes = append(nodes, &signedNode)

			return false
		},
	)

	return nodes, nil
}

func (s *immutableState) getSignedRuntimeRaw(id signature.PublicKey) ([]byte, error) {
	_, value := s.Snapshot.Get(signedRuntimeKeyFmt.Encode(&id))
	return value, nil
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

// GetRuntimes returns a list of all registered runtimes.
func (s *immutableState) GetRuntimes() ([]*registry.Runtime, error) {
	var runtimes []*registry.Runtime
	s.Snapshot.IterateRange(
		signedRuntimeKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !signedRuntimeKeyFmt.Decode(key) {
				return true
			}

			var signedRt registry.SignedRuntime
			if err := cbor.Unmarshal(value, &signedRt); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}
			var runtime registry.Runtime
			if err := cbor.Unmarshal(signedRt.Blob, &runtime); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			runtimes = append(runtimes, &runtime)

			return false
		},
	)

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
	var runtimes []*registry.SignedRuntime
	s.Snapshot.IterateRange(
		signedRuntimeKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !signedRuntimeKeyFmt.Decode(key) {
				return true
			}

			var signedRt registry.SignedRuntime
			if err := cbor.Unmarshal(value, &signedRt); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			runtimes = append(runtimes, &signedRt)

			return false
		},
	)

	return runtimes, nil
}

func (s *immutableState) getKeyManagerOperator() signature.PublicKey {
	_, value := s.Snapshot.Get(keyManagerOperatorKeyFmt.Encode())
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
	s.tree.Set(signedEntityKeyFmt.Encode(&ent.ID), sigEnt.MarshalCBOR())
}

func (s *MutableState) removeEntity(id signature.PublicKey) (entity.Entity, []node.Node) {
	var removedSignedEntity entity.SignedEntity
	var removedEntity entity.Entity
	var removedNodes []node.Node
	data, removed := s.tree.Remove(signedEntityKeyFmt.Encode(&id))
	if removed {
		// Remove any associated nodes.
		s.tree.IterateRangeInclusive(
			signedNodeByEntityKeyFmt.Encode(&id),
			nil,
			true,
			func(key, value []byte, version int64) bool {
				// Remove all dependent nodes.
				var entityID, nodeID signature.PublicKey
				if !signedNodeByEntityKeyFmt.Decode(key, &entityID, &nodeID) || !entityID.Equal(id) {
					return true
				}

				nodeData, _ := s.tree.Remove(signedNodeKeyFmt.Encode(&nodeID))
				s.tree.Remove(key)

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

	s.tree.Set(signedNodeKeyFmt.Encode(&node.ID), signedNode.MarshalCBOR())
	s.tree.Set(signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID), []byte(""))

	return nil
}

func (s *MutableState) removeNode(node *node.Node) {
	s.tree.Remove(signedNodeKeyFmt.Encode(&node.ID))
	s.tree.Remove(signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID))
}

func (s *MutableState) createRuntime(rt *registry.Runtime, sigRt *registry.SignedRuntime) error {
	entID := sigRt.Signature.PublicKey
	ent, err := s.getSignedEntityRaw(entID)
	if ent == nil || err != nil {
		return errEntityNotFound
	}

	s.tree.Set(signedRuntimeKeyFmt.Encode(&rt.ID), sigRt.MarshalCBOR())

	return nil
}

func (s *MutableState) setKeyManagerOperator(id signature.PublicKey) {
	if len(id) == 0 {
		return
	}

	value, _ := id.MarshalBinary()
	s.tree.Set(keyManagerOperatorKeyFmt.Encode(), value)
}

// NewMutableState creates a new mutable registry state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
