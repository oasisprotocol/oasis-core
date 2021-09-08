package state

import (
	"context"
	"errors"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmcrypto "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	_ registry.NodeLookup    = (*ImmutableState)(nil)
	_ registry.RuntimeLookup = (*ImmutableState)(nil)

	// signedEntityKeyFmt is the key format used for signed entities.
	//
	// Value is CBOR-serialized signed entity.
	signedEntityKeyFmt = keyformat.New(0x10, keyformat.H(&signature.PublicKey{}))
	// signedNodeKeyFmt is the key format used for signed nodes.
	//
	// Value is CBOR-serialized signed node.
	signedNodeKeyFmt = keyformat.New(0x11, keyformat.H(&signature.PublicKey{}))
	// signedNodeByEntityKeyFmt is the key format used for signed node by entity
	// index.
	//
	// Value is empty.
	signedNodeByEntityKeyFmt = keyformat.New(0x12, keyformat.H(&signature.PublicKey{}), keyformat.H(&signature.PublicKey{}))
	// runtimeKeyFmt is the key format used for runtimes.
	//
	// Value is CBOR-serialized runtime.
	runtimeKeyFmt = keyformat.New(0x13, keyformat.H(&common.Namespace{}))
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
	nodeStatusKeyFmt = keyformat.New(0x15, keyformat.H(&signature.PublicKey{}))
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized registry.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x16)
	// keyMapKeyFmt is the key format used for key-to-node-id map.
	//
	// This stores the consensus, P2P and TLS public keys to node ID mappings.
	//
	// Value is binary signature.PublicKey (node ID).
	keyMapKeyFmt = keyformat.New(0x17, keyformat.H(&signature.PublicKey{}))
	// suspendedRuntimeKeyFmt is the key format used for suspended runtimes.
	//
	// Value is CBOR-serialized runtime.
	suspendedRuntimeKeyFmt = keyformat.New(0x18, keyformat.H(&common.Namespace{}))
	// runtimeByEntityKeyFmt is the key format used for runtime by entity
	// index.
	//
	// Value is empty.
	runtimeByEntityKeyFmt = keyformat.New(0x19, keyformat.H(&signature.PublicKey{}), keyformat.H(&common.Namespace{}))
)

// ImmutableState is the immutable registry state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
}

func (s *ImmutableState) getSignedEntityRaw(ctx context.Context, id signature.PublicKey) ([]byte, error) {
	data, err := s.is.Get(ctx, signedEntityKeyFmt.Encode(&id))
	return data, abciAPI.UnavailableStateError(err)
}

// Entity looks up a registered entity by its identifier.
func (s *ImmutableState) Entity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	signedEntityRaw, err := s.getSignedEntityRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	if signedEntityRaw == nil {
		return nil, registry.ErrNoSuchEntity
	}

	var signedEntity entity.SignedEntity
	if err = cbor.Unmarshal(signedEntityRaw, &signedEntity); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	var entity entity.Entity
	if err = cbor.Unmarshal(signedEntity.Blob, &entity); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &entity, nil
}

// Entities returns a list of all registered entities.
func (s *ImmutableState) Entities(ctx context.Context) ([]*entity.Entity, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var entities []*entity.Entity
	for it.Seek(signedEntityKeyFmt.Encode()); it.Valid(); it.Next() {
		if !signedEntityKeyFmt.Decode(it.Key()) {
			break
		}

		var signedEntity entity.SignedEntity
		if err := cbor.Unmarshal(it.Value(), &signedEntity); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		var entity entity.Entity
		if err := cbor.Unmarshal(signedEntity.Blob, &entity); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		entities = append(entities, &entity)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return entities, nil
}

// SignedEntities returns a list of all registered entities (signed).
func (s *ImmutableState) SignedEntities(ctx context.Context) ([]*entity.SignedEntity, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var entities []*entity.SignedEntity
	for it.Seek(signedEntityKeyFmt.Encode()); it.Valid(); it.Next() {
		if !signedEntityKeyFmt.Decode(it.Key()) {
			break
		}

		var signedEntity entity.SignedEntity
		if err := cbor.Unmarshal(it.Value(), &signedEntity); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		entities = append(entities, &signedEntity)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return entities, nil
}

func (s *ImmutableState) getSignedNodeRaw(ctx context.Context, id signature.PublicKey) ([]byte, error) {
	data, err := s.is.Get(ctx, signedNodeKeyFmt.Encode(&id))
	return data, abciAPI.UnavailableStateError(err)
}

// Node looks up a specific node by its identifier.
func (s *ImmutableState) Node(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	signedNodeRaw, err := s.getSignedNodeRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	if signedNodeRaw == nil {
		return nil, registry.ErrNoSuchNode
	}

	var signedNode node.MultiSignedNode
	if err = cbor.Unmarshal(signedNodeRaw, &signedNode); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	var node node.Node
	if err = cbor.Unmarshal(signedNode.Blob, &node); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &node, nil
}

// NodeIDByConsensusAddress looks up a specific node ID by its consensus address.
//
// If you need to get the actual node descriptor, use NodeByConsensusAddress instead.
func (s *ImmutableState) NodeIDByConsensusAddress(ctx context.Context, address []byte) (signature.PublicKey, error) {
	rawID, err := s.is.Get(ctx, nodeByConsAddressKeyFmt.Encode(address))
	if err != nil {
		return signature.PublicKey{}, abciAPI.UnavailableStateError(err)
	}
	if rawID == nil {
		return signature.PublicKey{}, registry.ErrNoSuchNode
	}

	var id signature.PublicKey
	if err := id.UnmarshalBinary(rawID); err != nil {
		return signature.PublicKey{}, abciAPI.UnavailableStateError(err)
	}
	return id, nil
}

// NodeByConsensusAddress looks up a specific node by its consensus address.
func (s *ImmutableState) NodeByConsensusAddress(ctx context.Context, address []byte) (*node.Node, error) {
	id, err := s.NodeIDByConsensusAddress(ctx, address)
	if err != nil {
		return nil, err
	}
	return s.Node(ctx, id)
}

// Nodes returns a list of all registered nodes.
func (s *ImmutableState) Nodes(ctx context.Context) ([]*node.Node, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var nodes []*node.Node
	for it.Seek(signedNodeKeyFmt.Encode()); it.Valid(); it.Next() {
		if !signedNodeKeyFmt.Decode(it.Key()) {
			break
		}

		var signedNode node.MultiSignedNode
		if err := cbor.Unmarshal(it.Value(), &signedNode); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		var node node.Node
		if err := cbor.Unmarshal(signedNode.Blob, &node); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		nodes = append(nodes, &node)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	registry.SortNodeList(nodes)
	return nodes, nil
}

// SignedNodes returns a list of all registered nodes (in signed form).
func (s *ImmutableState) SignedNodes(ctx context.Context) ([]*node.MultiSignedNode, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var nodes []*node.MultiSignedNode
	for it.Seek(signedNodeKeyFmt.Encode()); it.Valid(); it.Next() {
		if !signedNodeKeyFmt.Decode(it.Key()) {
			break
		}

		var signedNode node.MultiSignedNode
		if err := cbor.Unmarshal(it.Value(), &signedNode); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		nodes = append(nodes, &signedNode)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return nodes, nil
}

func (s *ImmutableState) getRuntime(ctx context.Context, keyFmt *keyformat.KeyFormat, id common.Namespace) (*registry.Runtime, error) {
	raw, err := s.is.Get(ctx, keyFmt.Encode(&id))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, registry.ErrNoSuchRuntime
	}

	var runtime registry.Runtime
	if err := cbor.Unmarshal(raw, &runtime); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &runtime, nil
}

// Runtime looks up a runtime by its identifier and returns it.
//
// This excludes any suspended runtimes, use SuspendedRuntime to query
// suspended runtimes only.
func (s *ImmutableState) Runtime(ctx context.Context, id common.Namespace) (*registry.Runtime, error) {
	return s.getRuntime(ctx, runtimeKeyFmt, id)
}

// SuspendedRuntime looks up a suspended runtime by its identifier and
// returns it.
func (s *ImmutableState) SuspendedRuntime(ctx context.Context, id common.Namespace) (*registry.Runtime, error) {
	return s.getRuntime(ctx, suspendedRuntimeKeyFmt, id)
}

// AnyRuntime looks up either an active or suspended runtime by its identifier and returns it.
func (s *ImmutableState) AnyRuntime(ctx context.Context, id common.Namespace) (rt *registry.Runtime, err error) {
	rt, err = s.Runtime(ctx, id)
	if err == registry.ErrNoSuchRuntime {
		rt, err = s.SuspendedRuntime(ctx, id)
	}
	return
}

func (s *ImmutableState) iterateRuntimes(
	ctx context.Context,
	keyFmt *keyformat.KeyFormat,
	cb func(*registry.Runtime) error,
) error {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	for it.Seek(keyFmt.Encode()); it.Valid(); it.Next() {
		if !keyFmt.Decode(it.Key()) {
			break
		}

		var rt registry.Runtime
		if err := cbor.Unmarshal(it.Value(), &rt); err != nil {
			return abciAPI.UnavailableStateError(err)
		}

		if err := cb(&rt); err != nil {
			return err
		}
	}
	return abciAPI.UnavailableStateError(it.Err())
}

// Runtimes returns a list of all registered runtimes.
//
// This excludes any suspended runtimes.
func (s *ImmutableState) Runtimes(ctx context.Context) ([]*registry.Runtime, error) {
	var runtimes []*registry.Runtime
	err := s.iterateRuntimes(ctx, runtimeKeyFmt, func(rt *registry.Runtime) error {
		runtimes = append(runtimes, rt)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return runtimes, nil
}

// SuspendedRuntimes returns a list of all suspended runtimes.
func (s *ImmutableState) SuspendedRuntimes(ctx context.Context) ([]*registry.Runtime, error) {
	var runtimes []*registry.Runtime
	err := s.iterateRuntimes(ctx, suspendedRuntimeKeyFmt, func(rt *registry.Runtime) error {
		runtimes = append(runtimes, rt)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return runtimes, nil
}

// AllRuntimes returns a list of all registered runtimes (suspended included).
func (s *ImmutableState) AllRuntimes(ctx context.Context) ([]*registry.Runtime, error) {
	var runtimes []*registry.Runtime
	unpackFn := func(rt *registry.Runtime) error {
		runtimes = append(runtimes, rt)
		return nil
	}
	if err := s.iterateRuntimes(ctx, runtimeKeyFmt, unpackFn); err != nil {
		return nil, err
	}
	if err := s.iterateRuntimes(ctx, suspendedRuntimeKeyFmt, unpackFn); err != nil {
		return nil, err
	}
	return runtimes, nil
}

// NodeStatus returns a specific node status.
func (s *ImmutableState) NodeStatus(ctx context.Context, id signature.PublicKey) (*registry.NodeStatus, error) {
	value, err := s.is.Get(ctx, nodeStatusKeyFmt.Encode(&id))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if value == nil {
		return nil, registry.ErrNoSuchNode
	}

	var status registry.NodeStatus
	if err := cbor.Unmarshal(value, &status); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &status, nil
}

// GetEntityNodes returns nodes registered by given entity.
// Note that this returns both active and expired nodes.
func (s *ImmutableState) GetEntityNodes(ctx context.Context, id signature.PublicKey) ([]*node.Node, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	hID := keyformat.PreHashed(id.Hash())

	var nodes []*node.Node
	for it.Seek(signedNodeByEntityKeyFmt.Encode(&id)); it.Valid(); it.Next() {
		var hEntityID keyformat.PreHashed
		var hNodeID keyformat.PreHashed

		if !signedNodeByEntityKeyFmt.Decode(it.Key(), &hEntityID, &hNodeID) || !hEntityID.Equal(&hID) {
			break
		}

		rawSignedNode, err := s.is.Get(ctx, signedNodeKeyFmt.Encode(&hNodeID))
		if err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		if rawSignedNode == nil {
			return nil, abciAPI.UnavailableStateError(registry.ErrNoSuchNode)
		}
		var signedNode node.MultiSignedNode
		if err = cbor.Unmarshal(rawSignedNode, &signedNode); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		var node node.Node
		if err = cbor.Unmarshal(signedNode.Blob, &node); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		nodes = append(nodes, &node)
	}

	registry.SortNodeList(nodes)
	return nodes, nil
}

// HasEntityNodes checks whether an entity has any registered nodes.
func (s *ImmutableState) HasEntityNodes(ctx context.Context, id signature.PublicKey) (bool, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	hID := keyformat.PreHashed(id.Hash())
	if it.Seek(signedNodeByEntityKeyFmt.Encode(&id)); it.Valid() {
		var hEntityID keyformat.PreHashed
		if !signedNodeByEntityKeyFmt.Decode(it.Key(), &hEntityID) || !hEntityID.Equal(&hID) {
			return false, nil
		}
		return true, nil
	}
	return false, abciAPI.UnavailableStateError(it.Err())
}

// HasEntityRuntimes checks whether an entity has any registered runtimes.
func (s *ImmutableState) HasEntityRuntimes(ctx context.Context, id signature.PublicKey) (bool, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	hID := keyformat.PreHashed(id.Hash())
	if it.Seek(runtimeByEntityKeyFmt.Encode(&id)); it.Valid() {
		var hEntityID keyformat.PreHashed
		if !runtimeByEntityKeyFmt.Decode(it.Key(), &hEntityID) || !hEntityID.Equal(&hID) {
			return false, nil
		}
		return true, nil
	}
	return false, abciAPI.UnavailableStateError(it.Err())
}

// ConsensusParameters returns the registry consensus parameters.
func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*registry.ConsensusParameters, error) {
	raw, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, errors.New("tendermint/registry: expected consensus parameters to be present in app state")
	}

	var params registry.ConsensusParameters
	if err := cbor.Unmarshal(raw, &params); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &params, nil
}

// NodeBySubKey looks up a specific node by its consensus, P2P or TLS key.
func (s *ImmutableState) NodeBySubKey(ctx context.Context, key signature.PublicKey) (*node.Node, error) {
	rawID, err := s.is.Get(ctx, keyMapKeyFmt.Encode(&key))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if rawID == nil {
		return nil, registry.ErrNoSuchNode
	}

	var id signature.PublicKey
	if err := id.UnmarshalBinary(rawID); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return s.Node(ctx, id)
}

func NewImmutableState(ctx context.Context, state abciAPI.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := abciAPI.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{is}, nil
}

// MutableState is a mutable registry state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

// SetEntity sets a signed entity descriptor for a registered entity.
func (s *MutableState) SetEntity(ctx context.Context, ent *entity.Entity, sigEnt *entity.SignedEntity) error {
	err := s.ms.Insert(ctx, signedEntityKeyFmt.Encode(&ent.ID), cbor.Marshal(sigEnt))
	return abciAPI.UnavailableStateError(err)
}

// RemoveEntity removes a previously registered entity.
func (s *MutableState) RemoveEntity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	data, err := s.ms.RemoveExisting(ctx, signedEntityKeyFmt.Encode(&id))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data != nil {
		var removedSignedEntity entity.SignedEntity
		if err = cbor.Unmarshal(data, &removedSignedEntity); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		var removedEntity entity.Entity
		if err = cbor.Unmarshal(removedSignedEntity.Blob, &removedEntity); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		return &removedEntity, nil
	}
	return nil, registry.ErrNoSuchEntity
}

// SetNode sets a signed node descriptor for a registered node.
func (s *MutableState) SetNode(ctx context.Context, existingNode, node *node.Node, signedNode *node.MultiSignedNode) error { //nolint: gocyclo
	rawNodeID, err := node.ID.MarshalBinary()
	if err != nil {
		return err
	}

	if err = s.ms.Insert(ctx, signedNodeKeyFmt.Encode(&node.ID), cbor.Marshal(signedNode)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	if err = s.ms.Insert(ctx, signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID), []byte("")); err != nil {
		return abciAPI.UnavailableStateError(err)
	}

	// Update indices mapping various keys to nodes.

	// Consensus key.
	if existingNode != nil && !existingNode.Consensus.ID.Equal(node.Consensus.ID) {
		// Remove old consensus address mapping if it has changed.
		address := []byte(tmcrypto.PublicKeyToTendermint(&existingNode.Consensus.ID).Address())
		if err = s.ms.Remove(ctx, nodeByConsAddressKeyFmt.Encode(address)); err != nil {
			return abciAPI.UnavailableStateError(err)
		}
		if err = s.ms.Remove(ctx, keyMapKeyFmt.Encode(&existingNode.Consensus.ID)); err != nil {
			return abciAPI.UnavailableStateError(err)
		}
	}
	address := []byte(tmcrypto.PublicKeyToTendermint(&node.Consensus.ID).Address())
	if err = s.ms.Insert(ctx, nodeByConsAddressKeyFmt.Encode(address), rawNodeID); err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	if err = s.ms.Insert(ctx, keyMapKeyFmt.Encode(&node.Consensus.ID), rawNodeID); err != nil {
		return abciAPI.UnavailableStateError(err)
	}

	// Committee P2P key.
	if existingNode != nil && !existingNode.P2P.ID.Equal(node.P2P.ID) {
		// Remove old P2P key mapping if it has changed.
		if err = s.ms.Remove(ctx, keyMapKeyFmt.Encode(&existingNode.P2P.ID)); err != nil {
			return abciAPI.UnavailableStateError(err)
		}
	}
	if err = s.ms.Insert(ctx, keyMapKeyFmt.Encode(&node.P2P.ID), rawNodeID); err != nil {
		return abciAPI.UnavailableStateError(err)
	}

	// VRF key.
	if existingNode != nil && existingNode.VRF != nil {
		// Remove old VRF key if it has changed.
		if node.VRF == nil || !existingNode.VRF.ID.Equal(node.VRF.ID) {
			if err = s.ms.Remove(ctx, keyMapKeyFmt.Encode(&existingNode.VRF.ID)); err != nil {
				return abciAPI.UnavailableStateError(err)
			}
		}
	}
	if node.VRF != nil {
		if err = s.ms.Insert(ctx, keyMapKeyFmt.Encode(&node.VRF.ID), rawNodeID); err != nil {
			return abciAPI.UnavailableStateError(err)
		}
	}

	// Committee TLS key.
	if existingNode != nil && !existingNode.TLS.PubKey.Equal(node.TLS.PubKey) {
		// Remove old TLS key mapping if it has changed.
		if err = s.ms.Remove(ctx, keyMapKeyFmt.Encode(&existingNode.TLS.PubKey)); err != nil {
			return abciAPI.UnavailableStateError(err)
		}
	}
	if err = s.ms.Insert(ctx, keyMapKeyFmt.Encode(&node.TLS.PubKey), rawNodeID); err != nil {
		return abciAPI.UnavailableStateError(err)
	}

	return nil
}

// RemoveNode removes a registered node.
func (s *MutableState) RemoveNode(ctx context.Context, node *node.Node) error {
	if err := s.ms.Remove(ctx, signedNodeKeyFmt.Encode(&node.ID)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	if err := s.ms.Remove(ctx, signedNodeByEntityKeyFmt.Encode(&node.EntityID, &node.ID)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	if err := s.ms.Remove(ctx, nodeStatusKeyFmt.Encode(&node.ID)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}

	address := []byte(tmcrypto.PublicKeyToTendermint(&node.Consensus.ID).Address())
	if err := s.ms.Remove(ctx, nodeByConsAddressKeyFmt.Encode(address)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}

	if err := s.ms.Remove(ctx, keyMapKeyFmt.Encode(&node.Consensus.ID)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	if err := s.ms.Remove(ctx, keyMapKeyFmt.Encode(&node.P2P.ID)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	if err := s.ms.Remove(ctx, keyMapKeyFmt.Encode(&node.TLS.PubKey)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}

	if node.VRF != nil {
		if err := s.ms.Remove(ctx, keyMapKeyFmt.Encode(&node.VRF.ID)); err != nil {
			return abciAPI.UnavailableStateError(err)
		}
	}

	return nil
}

// SetRuntime sets a runtime descriptor for a registered runtime.
func (s *MutableState) SetRuntime(ctx context.Context, rt *registry.Runtime, suspended bool) error {
	if err := s.ms.Insert(ctx, runtimeByEntityKeyFmt.Encode(&rt.EntityID, &rt.ID), []byte("")); err != nil {
		return abciAPI.UnavailableStateError(err)
	}

	var err error
	if suspended {
		err = s.ms.Insert(ctx, suspendedRuntimeKeyFmt.Encode(&rt.ID), cbor.Marshal(rt))
	} else {
		err = s.ms.Insert(ctx, runtimeKeyFmt.Encode(&rt.ID), cbor.Marshal(rt))
	}
	return abciAPI.UnavailableStateError(err)
}

// SuspendRuntime marks a runtime as suspended.
func (s *MutableState) SuspendRuntime(ctx context.Context, id common.Namespace) error {
	data, err := s.ms.RemoveExisting(ctx, runtimeKeyFmt.Encode(&id))
	if err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return registry.ErrNoSuchRuntime
	}
	err = s.ms.Insert(ctx, suspendedRuntimeKeyFmt.Encode(&id), data)
	return abciAPI.UnavailableStateError(err)
}

// ResumeRuntime resumes a previously suspended runtime.
func (s *MutableState) ResumeRuntime(ctx context.Context, id common.Namespace) error {
	data, err := s.ms.RemoveExisting(ctx, suspendedRuntimeKeyFmt.Encode(&id))
	if err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return registry.ErrNoSuchRuntime
	}
	err = s.ms.Insert(ctx, runtimeKeyFmt.Encode(&id), data)
	return abciAPI.UnavailableStateError(err)
}

// SetNodeStatus sets a status for a registered node.
func (s *MutableState) SetNodeStatus(ctx context.Context, id signature.PublicKey, status *registry.NodeStatus) error {
	err := s.ms.Insert(ctx, nodeStatusKeyFmt.Encode(&id), cbor.Marshal(status))
	return abciAPI.UnavailableStateError(err)
}

// SetConsensusParameters sets registry consensus parameters.
//
// NOTE: This method must only be called from InitChain/EndBlock contexts.
func (s *MutableState) SetConsensusParameters(ctx context.Context, params *registry.ConsensusParameters) error {
	if err := s.is.CheckContextMode(ctx, []abciAPI.ContextMode{abciAPI.ContextInitChain, abciAPI.ContextEndBlock}); err != nil {
		return err
	}
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return abciAPI.UnavailableStateError(err)
}

// NewMutableState creates a new mutable registry state wrapper.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&abciAPI.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}
