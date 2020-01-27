package state

import (
	"errors"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	tmcrypto "github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var (
	_ registry.NodeLookup = (*ImmutableState)(nil)

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
	signedRuntimeKeyFmt = keyformat.New(0x13, &common.Namespace{})
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
	// Value is CBOR-serialized registry.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x16)
	// keyMapKeyFmt is the key format used for key-to-node-id map.
	// This stores the consensus and P2P to Node ID mappings.
	//
	// Value is binary signature.PublicKey (node ID).
	keyMapKeyFmt = keyformat.New(0x17, &signature.PublicKey{})
	// certificateMapKeyFmt is the key format used for certificate-to-node-id map.
	// This stores the hash-of-certificate to Node ID mappings.
	//
	// Value is binary signature.PublicKey (node ID).
	certificateMapKeyFmt = keyformat.New(0x18, &hash.Hash{})
	// suspendedRuntimeKeyFmt is the key format used for suspended runtimes.
	//
	// Value is CBOR-serialized signed runtime.
	suspendedRuntimeKeyFmt = keyformat.New(0x19, &common.Namespace{})
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

	var signedNode node.MultiSignedNode
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

			var signedNode node.MultiSignedNode
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

func (s *ImmutableState) SignedNodes() ([]*node.MultiSignedNode, error) {
	var nodes []*node.MultiSignedNode
	s.Snapshot.IterateRange(
		signedNodeKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !signedNodeKeyFmt.Decode(key) {
				return true
			}

			var signedNode node.MultiSignedNode
			if err := cbor.Unmarshal(value, &signedNode); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			nodes = append(nodes, &signedNode)

			return false
		},
	)

	return nodes, nil
}

func (s *ImmutableState) getSignedRuntime(keyFmt *keyformat.KeyFormat, id common.Namespace) (*registry.SignedRuntime, error) {
	_, raw := s.Snapshot.Get(keyFmt.Encode(&id))
	if raw == nil {
		return nil, registry.ErrNoSuchRuntime
	}

	var signedRuntime registry.SignedRuntime
	if err := cbor.Unmarshal(raw, &signedRuntime); err != nil {
		return nil, err
	}
	return &signedRuntime, nil
}

func (s *ImmutableState) getRuntime(keyFmt *keyformat.KeyFormat, id common.Namespace) (*registry.Runtime, error) {
	signedRuntime, err := s.getSignedRuntime(keyFmt, id)
	if err != nil {
		return nil, err
	}
	var runtime registry.Runtime
	if err = cbor.Unmarshal(signedRuntime.Blob, &runtime); err != nil {
		return nil, err
	}
	return &runtime, nil
}

// Runtime looks up a runtime by its identifier and returns it.
//
// This excludes any suspended runtimes, use SuspendedRuntime to query
// suspended runtimes only.
func (s *ImmutableState) Runtime(id common.Namespace) (*registry.Runtime, error) {
	return s.getRuntime(signedRuntimeKeyFmt, id)
}

// SuspendedRuntime looks up a suspended runtime by its identifier and
// returns it.
func (s *ImmutableState) SuspendedRuntime(id common.Namespace) (*registry.Runtime, error) {
	return s.getRuntime(suspendedRuntimeKeyFmt, id)
}

// AnyRuntime looks up either an active or suspended runtime by its identifier and returns it.
func (s *ImmutableState) AnyRuntime(id common.Namespace) (rt *registry.Runtime, err error) {
	rt, err = s.Runtime(id)
	if err == registry.ErrNoSuchRuntime {
		rt, err = s.SuspendedRuntime(id)
	}
	return
}

// SignedRuntime looks up a (signed) runtime by its identifier and returns it.
//
// This excludes any suspended runtimes, use SuspendedSignedRuntime to query
// suspended runtimes only.
func (s *ImmutableState) SignedRuntime(id common.Namespace) (*registry.SignedRuntime, error) {
	return s.getSignedRuntime(signedRuntimeKeyFmt, id)
}

// SignedSuspendedRuntime looks up a (signed) suspended runtime by its identifier and returns it.
func (s *ImmutableState) SignedSuspendedRuntime(id common.Namespace) (*registry.SignedRuntime, error) {
	return s.getSignedRuntime(suspendedRuntimeKeyFmt, id)
}

func (s *ImmutableState) iterateRuntimes(
	keyFmt *keyformat.KeyFormat,
	cb func(*registry.SignedRuntime),
) {
	s.Snapshot.IterateRange(
		keyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !keyFmt.Decode(key) {
				return true
			}

			var signedRt registry.SignedRuntime
			if err := cbor.Unmarshal(value, &signedRt); err != nil {
				panic("tendermint/registry: corrupted state: " + err.Error())
			}

			cb(&signedRt)

			return false
		},
	)
}

// SignedRuntimes returns a list of all registered runtimes (signed).
//
// This excludes any suspended runtimes.
func (s *ImmutableState) SignedRuntimes() ([]*registry.SignedRuntime, error) {
	var runtimes []*registry.SignedRuntime
	s.iterateRuntimes(signedRuntimeKeyFmt, func(rt *registry.SignedRuntime) {
		runtimes = append(runtimes, rt)
	})

	return runtimes, nil
}

// SuspendedRuntimes returns a list of all suspended runtimes (signed).
func (s *ImmutableState) SuspendedRuntimes() ([]*registry.SignedRuntime, error) {
	var runtimes []*registry.SignedRuntime
	s.iterateRuntimes(suspendedRuntimeKeyFmt, func(rt *registry.SignedRuntime) {
		runtimes = append(runtimes, rt)
	})

	return runtimes, nil
}

// AllSignedRuntimes returns a list of all runtimes (suspended included).
func (s *ImmutableState) AllSignedRuntimes() ([]*registry.SignedRuntime, error) {
	var runtimes []*registry.SignedRuntime
	s.iterateRuntimes(signedRuntimeKeyFmt, func(rt *registry.SignedRuntime) {
		runtimes = append(runtimes, rt)
	})
	s.iterateRuntimes(suspendedRuntimeKeyFmt, func(rt *registry.SignedRuntime) {
		runtimes = append(runtimes, rt)
	})

	return runtimes, nil
}

// Runtimes returns a list of all registered runtimes.
//
// This excludes any suspended runtimes.
func (s *ImmutableState) Runtimes() ([]*registry.Runtime, error) {
	var runtimes []*registry.Runtime
	s.iterateRuntimes(signedRuntimeKeyFmt, func(sigRt *registry.SignedRuntime) {
		var rt registry.Runtime
		if err := cbor.Unmarshal(sigRt.Blob, &rt); err != nil {
			panic("tendermint/registry: corrupted state: " + err.Error())
		}
		runtimes = append(runtimes, &rt)
	})

	return runtimes, nil
}

// AllRuntimes returns a list of all registered runtimes (suspended included).
func (s *ImmutableState) AllRuntimes() ([]*registry.Runtime, error) {
	var runtimes []*registry.Runtime
	unpackFn := func(sigRt *registry.SignedRuntime) {
		var rt registry.Runtime
		if err := cbor.Unmarshal(sigRt.Blob, &rt); err != nil {
			panic("tendermint/registry: corrupted state: " + err.Error())
		}
		runtimes = append(runtimes, &rt)
	}
	s.iterateRuntimes(signedRuntimeKeyFmt, unpackFn)
	s.iterateRuntimes(suspendedRuntimeKeyFmt, unpackFn)

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

func (s *ImmutableState) NodeByConsensusOrP2PKey(key signature.PublicKey) (*node.Node, error) {
	_, rawID := s.Snapshot.Get(keyMapKeyFmt.Encode(&key))
	if rawID == nil {
		return nil, registry.ErrNoSuchNode
	}

	var id signature.PublicKey
	if err := id.UnmarshalBinary(rawID); err != nil {
		return nil, err
	}
	return s.Node(id)
}

// Hashes a node's committee certificate into a key for the certificate to node ID map.
func nodeCertificateToMapKey(cert []byte) hash.Hash {
	var h hash.Hash
	h.FromBytes(cert)
	return h
}

func (s *ImmutableState) NodeByCertificate(cert []byte) (*node.Node, error) {
	certHash := nodeCertificateToMapKey(cert)
	_, rawID := s.Snapshot.Get(certificateMapKeyFmt.Encode(&certHash))
	if rawID == nil {
		return nil, registry.ErrNoSuchNode
	}

	var id signature.PublicKey
	if err := id.UnmarshalBinary(rawID); err != nil {
		return nil, err
	}
	return s.Node(id)
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

func (s *MutableState) SetEntity(ent *entity.Entity, sigEnt *entity.SignedEntity) {
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

func (s *MutableState) SetNode(node *node.Node, signedNode *node.MultiSignedNode) error {
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

	s.tree.Set(keyMapKeyFmt.Encode(&node.Consensus.ID), rawNodeID)
	s.tree.Set(keyMapKeyFmt.Encode(&node.P2P.ID), rawNodeID)

	certHash := nodeCertificateToMapKey(node.Committee.Certificate)
	s.tree.Set(certificateMapKeyFmt.Encode(&certHash), rawNodeID)

	return nil
}

func (s *MutableState) RemoveNode(node *node.Node) {
	s.tree.Remove(signedNodeKeyFmt.Encode(&node.ID))
	s.tree.Remove(signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID))
	s.tree.Remove(nodeStatusKeyFmt.Encode(&node.ID))

	address := []byte(tmcrypto.PublicKeyToTendermint(&node.Consensus.ID).Address())
	s.tree.Remove(nodeByConsAddressKeyFmt.Encode(address))

	s.tree.Remove(keyMapKeyFmt.Encode(&node.Consensus.ID))
	s.tree.Remove(keyMapKeyFmt.Encode(&node.P2P.ID))

	certHash := nodeCertificateToMapKey(node.Committee.Certificate)
	s.tree.Remove(certificateMapKeyFmt.Encode(&certHash))
}

func (s *MutableState) SetRuntime(rt *registry.Runtime, sigRt *registry.SignedRuntime, suspended bool) error {
	entID := sigRt.Signature.PublicKey
	ent, err := s.getSignedEntityRaw(entID)
	if ent == nil || err != nil {
		return registry.ErrNoSuchEntity
	}

	if suspended {
		s.tree.Set(suspendedRuntimeKeyFmt.Encode(&rt.ID), cbor.Marshal(sigRt))
	} else {
		s.tree.Set(signedRuntimeKeyFmt.Encode(&rt.ID), cbor.Marshal(sigRt))
	}

	return nil
}

func (s *MutableState) SuspendRuntime(id common.Namespace) error {
	_, raw := s.Snapshot.Get(signedRuntimeKeyFmt.Encode(&id))
	if raw == nil {
		return registry.ErrNoSuchRuntime
	}

	s.tree.Remove(signedRuntimeKeyFmt.Encode(&id))
	s.tree.Set(suspendedRuntimeKeyFmt.Encode(&id), raw)
	return nil
}

func (s *MutableState) ResumeRuntime(id common.Namespace) error {
	_, raw := s.Snapshot.Get(suspendedRuntimeKeyFmt.Encode(&id))
	if raw == nil {
		return registry.ErrNoSuchRuntime
	}

	s.tree.Remove(suspendedRuntimeKeyFmt.Encode(&id))
	s.tree.Set(signedRuntimeKeyFmt.Encode(&id), raw)
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
