package state

import (
	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/node"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
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
)

type ImmutableState struct {
	*abci.ImmutableState
}

func (s *ImmutableState) getSignedEntityRaw(id signature.PublicKey) ([]byte, error) {
	_, value := s.Snapshot.Get(signedEntityKeyFmt.Encode(&id))
	return value, nil
}

func (s *ImmutableState) Entity(id signature.PublicKey) (*entity.Entity, error) {
	signedEntityRaw, err := s.getSignedEntityRaw(id)
	if err != nil || signedEntityRaw == nil {
		return nil, registry.ErrNoSuchEntity
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

func (s *ImmutableState) Entities() ([]*entity.Entity, error) {
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

func (s *ImmutableState) SignedEntities() ([]*entity.SignedEntity, error) {
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

func (s *ImmutableState) getSignedNodeRaw(id signature.PublicKey) ([]byte, error) {
	_, value := s.Snapshot.Get(signedNodeKeyFmt.Encode(&id))
	return value, nil
}

func (s *ImmutableState) Node(id signature.PublicKey) (*node.Node, error) {
	signedNodeRaw, err := s.getSignedNodeRaw(id)
	if err != nil {
		return nil, err
	}
	if signedNodeRaw == nil {
		return nil, registry.ErrNoSuchNode
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

func (s *ImmutableState) Nodes() ([]*node.Node, error) {
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

func (s *ImmutableState) SignedNodes() ([]*node.SignedNode, error) {
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

func (s *ImmutableState) getSignedRuntimeRaw(id signature.PublicKey) ([]byte, error) {
	_, value := s.Snapshot.Get(signedRuntimeKeyFmt.Encode(&id))
	return value, nil
}

// GetRuntime looks up a runtime by its identifier and returns it.
func (s *ImmutableState) Runtime(id signature.PublicKey) (*registry.Runtime, error) {
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
func (s *ImmutableState) Runtimes() ([]*registry.Runtime, error) {
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

func (s *ImmutableState) SignedRuntimes() ([]*registry.SignedRuntime, error) {
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

func (s *ImmutableState) KeyManagerOperator() signature.PublicKey {
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

func NewImmutableState(state *abci.ApplicationState, version int64) (*ImmutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{inner}, nil
}

// MutableState is a mutable registry state wrapper.
type MutableState struct {
	*ImmutableState

	tree *iavl.MutableTree
}

func (s *MutableState) CreateEntity(ent *entity.Entity, sigEnt *entity.SignedEntity) {
	s.tree.Set(signedEntityKeyFmt.Encode(&ent.ID), sigEnt.MarshalCBOR())
}

func (s *MutableState) RemoveEntity(id signature.PublicKey) (entity.Entity, []node.Node) {
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

func (s *MutableState) CreateNode(node *node.Node, signedNode *node.SignedNode) error {
	// Ensure that the entity exists.
	ent, err := s.getSignedEntityRaw(node.EntityID)
	if ent == nil || err != nil {
		return registry.ErrNoSuchEntity
	}

	s.tree.Set(signedNodeKeyFmt.Encode(&node.ID), signedNode.MarshalCBOR())
	s.tree.Set(signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID), []byte(""))

	return nil
}

func (s *MutableState) RemoveNode(node *node.Node) {
	s.tree.Remove(signedNodeKeyFmt.Encode(&node.ID))
	s.tree.Remove(signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID))
}

func (s *MutableState) CreateRuntime(rt *registry.Runtime, sigRt *registry.SignedRuntime) error {
	entID := sigRt.Signature.PublicKey
	ent, err := s.getSignedEntityRaw(entID)
	if ent == nil || err != nil {
		return registry.ErrNoSuchEntity
	}

	s.tree.Set(signedRuntimeKeyFmt.Encode(&rt.ID), sigRt.MarshalCBOR())

	return nil
}

func (s *MutableState) SetKeyManagerOperator(id signature.PublicKey) {
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
		ImmutableState: &ImmutableState{inner},
		tree:           tree,
	}
}
