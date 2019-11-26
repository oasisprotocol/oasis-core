package state

import (
	"errors"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	tmcrypto "github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var (
	// signedEntityKeyFmt is the key format used for signed entities.
	//
	// Value is CBOR-serialized signed entity.
	signedEntityKeyFmt = keyformat.New(0x10, &signature.PublicKey{})
	// signedNodeKeyFmt is the key format used for signed nodes.
	//
	// Value is CBOR-serialized signed node.
	signedNodeKeyFmt = keyformat.New(0x11, &signature.PublicKey{})
	// signedNodeByEntityKeyFmt is the key format used for signed node by entity
	// index.
	//
	// Value is empty.
	signedNodeByEntityKeyFmt = keyformat.New(0x12, &signature.PublicKey{}, &signature.PublicKey{})
	// signedRuntimeKeyFmt is the key format used for signed runtimes.
	//
	// Value is CBOR-serialized signed runtime.
	signedRuntimeKeyFmt = keyformat.New(0x13, &signature.PublicKey{})
	// nodeByConsAddressKeyFmt is the key format used for the consensus address to
	// node public key mapping.
	//
	// The only reason why this is needed is because Tendermint only gives you
	// the validator address (which is the truncated SHA-256 of the public key) in
	// evidence instead of the actual public key.
	//
	// Value is binary node public key.
	nodeByConsAddressKeyFmt = keyformat.New(0x14, []byte{})
	// nodeStatusKeyFmt is the key format used for node statuses.
	//
	// Value is CBOR-serialized node status.
	nodeStatusKeyFmt = keyformat.New(0x15, &signature.PublicKey{})
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized roothash.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x16)
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

func (s *ImmutableState) NodeByConsensusAddress(address []byte) (*node.Node, error) {
	_, rawID := s.Snapshot.Get(nodeByConsAddressKeyFmt.Encode(address))
	if rawID == nil {
		return nil, registry.ErrNoSuchNode
	}

	var id signature.PublicKey
	if err := id.UnmarshalBinary(rawID); err != nil {
		return nil, err
	}
	return s.Node(id)
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

func (s *ImmutableState) NodeStatus(id signature.PublicKey) (*registry.NodeStatus, error) {
	_, value := s.Snapshot.Get(nodeStatusKeyFmt.Encode(&id))
	if value == nil {
		return nil, registry.ErrNoSuchNode
	}

	var status registry.NodeStatus
	if err := cbor.Unmarshal(value, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (s *ImmutableState) NodeStatuses() (map[signature.PublicKey]*registry.NodeStatus, error) {
	statuses := make(map[signature.PublicKey]*registry.NodeStatus)
	s.Snapshot.IterateRange(
		nodeStatusKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			var nodeID signature.PublicKey
			if !nodeStatusKeyFmt.Decode(key, &nodeID) {
				return true
			}

			var status registry.NodeStatus
			if err := cbor.Unmarshal(value, &status); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			statuses[nodeID] = &status

			return false
		},
	)

	return statuses, nil
}

func (s *ImmutableState) HasEntityNodes(id signature.PublicKey) (bool, error) {
	result := true
	s.Snapshot.IterateRange(
		signedNodeByEntityKeyFmt.Encode(&id),
		nil,
		true,
		func(key, value []byte) bool {
			var entityID signature.PublicKey
			if !signedNodeByEntityKeyFmt.Decode(key, &entityID) || !entityID.Equal(id) {
				result = false
			}
			// Stop immediately as we are only interested in one result.
			return true
		},
	)
	return result, nil
}

func (s *ImmutableState) NumEntityNodes(id signature.PublicKey) (int, error) {
	var n int
	s.Snapshot.IterateRange(
		signedNodeByEntityKeyFmt.Encode(&id),
		nil,
		true,
		func(key, value []byte) bool {
			var entityID signature.PublicKey
			if !signedNodeByEntityKeyFmt.Decode(key, &entityID) || !entityID.Equal(id) {
				return true
			}

			n++

			return false
		},
	)
	return n, nil
}

func (s *ImmutableState) ConsensusParameters() (*registry.ConsensusParameters, error) {
	_, raw := s.Snapshot.Get(parametersKeyFmt.Encode())
	if raw == nil {
		return nil, errors.New("tendermint/registry: expected consensus parameters to be present in app state")
	}

	var params registry.ConsensusParameters
	err := cbor.Unmarshal(raw, &params)
	return &params, err
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
	s.tree.Set(signedEntityKeyFmt.Encode(&ent.ID), cbor.Marshal(sigEnt))
}

func (s *MutableState) RemoveEntity(id signature.PublicKey) (*entity.Entity, error) {
	data, removed := s.tree.Remove(signedEntityKeyFmt.Encode(&id))
	if removed {
		var removedSignedEntity entity.SignedEntity
		var removedEntity entity.Entity

		cbor.MustUnmarshal(data, &removedSignedEntity)
		cbor.MustUnmarshal(removedSignedEntity.Blob, &removedEntity)
		return &removedEntity, nil
	}

	return nil, registry.ErrNoSuchEntity
}

func (s *MutableState) CreateNode(node *node.Node, signedNode *node.SignedNode) error {
	// Ensure that the entity exists.
	ent, err := s.getSignedEntityRaw(node.EntityID)
	if ent == nil || err != nil {
		return registry.ErrNoSuchEntity
	}

	s.tree.Set(signedNodeKeyFmt.Encode(&node.ID), cbor.Marshal(signedNode))
	s.tree.Set(signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID), []byte(""))

	address := []byte(tmcrypto.PublicKeyToTendermint(&node.Consensus.ID).Address())
	rawNodeID, err := node.ID.MarshalBinary()
	if err != nil {
		return err
	}
	s.tree.Set(nodeByConsAddressKeyFmt.Encode(address), rawNodeID)

	return nil
}

func (s *MutableState) RemoveNode(node *node.Node) {
	s.tree.Remove(signedNodeKeyFmt.Encode(&node.ID))
	s.tree.Remove(signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID))
	s.tree.Remove(nodeStatusKeyFmt.Encode(&node.ID))

	address := []byte(tmcrypto.PublicKeyToTendermint(&node.Consensus.ID).Address())
	s.tree.Remove(nodeByConsAddressKeyFmt.Encode(address))
}

func (s *MutableState) CreateRuntime(rt *registry.Runtime, sigRt *registry.SignedRuntime) error {
	entID := sigRt.Signature.PublicKey
	ent, err := s.getSignedEntityRaw(entID)
	if ent == nil || err != nil {
		return registry.ErrNoSuchEntity
	}

	s.tree.Set(signedRuntimeKeyFmt.Encode(&rt.ID), cbor.Marshal(sigRt))

	return nil
}

func (s *MutableState) SetNodeStatus(id signature.PublicKey, status *registry.NodeStatus) error {
	s.tree.Set(nodeStatusKeyFmt.Encode(&id), cbor.Marshal(status))
	return nil
}

func (s *MutableState) SetConsensusParameters(params *registry.ConsensusParameters) {
	s.tree.Set(parametersKeyFmt.Encode(), cbor.Marshal(params))
}

// NewMutableState creates a new mutable registry state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		ImmutableState: &ImmutableState{inner},
		tree:           tree,
	}
}
