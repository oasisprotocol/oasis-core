// Package api implements the runtime and entity registry APIs.
package api

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"time"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
)

const (
	// TimestampValidFor is the number of seconds that a timestamp in a
	// register or deregister call is considered valid.
	// Default is 15 minutes.
	TimestampValidFor = uint64(15 * 60)
)

var (
	// RegisterEntitySignatureContext is the context used for entity
	// registration.
	RegisterEntitySignatureContext = []byte("EkEntReg")

	// RegisterGenesisEntitySignatureContext is the context used for
	// entity registration in the genesis document.
	RegisterGenesisEntitySignatureContext = []byte("EkEntGen")

	// DeregisterEntitySignatureContext is the context used for entity
	// deregistration.
	DeregisterEntitySignatureContext = []byte("EkEDeReg")

	// RegisterNodeSignatureContext is the context used for node
	// registration.
	RegisterNodeSignatureContext = []byte("EkNodReg")

	// RegisterGenesisNodeSignatureContext is the context used for
	/// node registration in the genesis document.
	RegisterGenesisNodeSignatureContext = []byte("EkNodReg")

	// RegisterRuntimeSignatureContext is the context used for runtime
	// registration.
	RegisterRuntimeSignatureContext = []byte("EkRunReg")

	// RegisterGenesisRuntimeSignatureContext is the context used for
	// runtime registation in the genesis document.
	RegisterGenesisRuntimeSignatureContext = []byte("EkRunGen")

	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New("registry: invalid argument")

	// ErrInvalidSignature is the error returned on an invalid signature.
	ErrInvalidSignature = errors.New("registry: invalid signature")

	// ErrBadEntityForNode is the error returned when a node registration
	// with an unknown entity is attempted.
	ErrBadEntityForNode = errors.New("registry: unknown entity in node registration")

	// ErrBadEntityForRuntime is the error returned when a runtime
	// registration with an unknown entity is attempted.
	ErrBadEntityForRuntime = errors.New("registry: unknown entity in runtime registration")

	// ErrNoSuchEntity is the error returned when an entity does not exist.
	ErrNoSuchEntity = errors.New("registry: no such entity")

	// ErrNoSuchNode is the error returned when an node does not exist.
	ErrNoSuchNode = errors.New("registry: no such node")

	// ErrNoSuchRuntime is the error returned when an runtime does not exist.
	ErrNoSuchRuntime = errors.New("registry: no such runtime")

	// ErrInvalidTimestamp is the error returned when a timestamp is invalid.
	ErrInvalidTimestamp = errors.New("registry: invalid timestamp")

	// ErrNodeExpired is the error returned when a node is expired.
	ErrNodeExpired = errors.New("registry: node expired")

	// ErrForbidden is the error returned when an operation is forbiden by
	// policy.
	ErrForbidden = errors.New("registry: forbidden by policy")

	// ErrNodeUpdateNotAllowed is the error returned when trying to update an existing node with unallowed changes.
	ErrNodeUpdateNotAllowed = errors.New("registry: node update not allowed")
)

// Backend is a registry implementation.
type Backend interface {
	// RegisterEntity registers and or updates an entity with the registry.
	//
	// The signature should be made using RegisterEntitySignatureContext.
	RegisterEntity(context.Context, *entity.SignedEntity) error

	// DeregisterEntity deregisters an entity.
	//
	// The signature should be made using DeregisterEntitySignatureContext.
	DeregisterEntity(context.Context, *signature.Signed) error

	// GetEntity gets an entity by ID.
	GetEntity(context.Context, signature.PublicKey) (*entity.Entity, error)

	// GetEntities gets a list of all registered entities.
	GetEntities(context.Context) ([]*entity.Entity, error)

	// WatchEntities returns a channel that produces a stream of
	// EntityEvent on entity registration changes.
	WatchEntities() (<-chan *EntityEvent, *pubsub.Subscription)

	// RegisterNode registers and or updates a node with the registry.
	//
	// The signature should be made using RegisterNodeSignatureContext.
	RegisterNode(context.Context, *node.SignedNode) error

	// GetNode gets a node by ID.
	GetNode(context.Context, signature.PublicKey) (*node.Node, error)

	// GetNodes gets a list of all registered nodes.
	GetNodes(context.Context) ([]*node.Node, error)

	// GetNodesForEntity gets a list of nodes registered to an entity ID.
	GetNodesForEntity(context.Context, signature.PublicKey) []*node.Node

	// GetNodeTransport gets a registered node's transport information.
	GetNodeTransport(context.Context, signature.PublicKey) (*NodeTransport, error)

	// WatchNodes returns a channel that produces a stream of
	// NodeEvent on node registration changes.
	WatchNodes() (<-chan *NodeEvent, *pubsub.Subscription)

	// WatchNodeList returns a channel that produces a stream of NodeList.
	// Upon subscription, the node list for the current epoch will be sent
	// immediately if available.
	//
	// Each node list will be sorted by node ID in lexographically ascending
	// order.
	WatchNodeList() (<-chan *NodeList, *pubsub.Subscription)

	// RegisterRuntime registers a runtime.
	RegisterRuntime(context.Context, *SignedRuntime) error

	// GetRuntime gets a runtime by ID.
	GetRuntime(context.Context, signature.PublicKey) (*Runtime, error)

	// GetRuntimes returns the registered Runtimes at the specified
	// block height.
	GetRuntimes(context.Context, int64) ([]*Runtime, error)

	// GetNodeList returns the NodeList at the specified block height.
	GetNodeList(context.Context, int64) (*NodeList, error)

	// WatchRuntimes returns a stream of Runtime.  Upon subscription,
	// all runtimes will be sent immediately.
	WatchRuntimes() (<-chan *Runtime, *pubsub.Subscription)

	// Cleanup cleans up the registry backend.
	Cleanup()
}

// NodeTransport is a registered node's transport information required to
// establish a secure connection with the node.
type NodeTransport struct {
	Addresses   []node.Address
	Certificate []byte
}

// EntityEvent is the event that is returned via WatchEntities to signify
// entity registration changes and updates.
type EntityEvent struct {
	Entity         *entity.Entity
	IsRegistration bool
}

// NodeEvent is the event that is returned via WatchNodes to signify node
// registration changes and updates.
type NodeEvent struct {
	Node           *node.Node
	IsRegistration bool
}

// NodeList is a per-epoch immutable node list.
type NodeList struct {
	Nodes []*node.Node
}

type Timestamp uint64

// MarshalCBOR serializes the Timestamp type into a CBOR byte vector.
func (t *Timestamp) MarshalCBOR() []byte {
	return cbor.Marshal(t)
}

// UnmarshalCBOR deserializes a CBOR byte vector into a Timestamp.
func (t *Timestamp) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, t)
}

// VerifyRegisterEntityArgs verifies arguments for RegisterEntity.
func VerifyRegisterEntityArgs(logger *logging.Logger, sigEnt *entity.SignedEntity, isGenesis bool) (*entity.Entity, error) {
	// XXX: Ensure ent is well-formed.
	var ent entity.Entity
	if sigEnt == nil {
		return nil, ErrInvalidArgument
	}

	var ctx []byte
	switch isGenesis {
	case true:
		ctx = RegisterGenesisEntitySignatureContext
	case false:
		ctx = RegisterEntitySignatureContext
	}

	if err := sigEnt.Open(ctx, &ent); err != nil {
		logger.Error("RegisterEntity: invalid signature",
			"signed_entity", sigEnt,
		)
		return nil, ErrInvalidSignature
	}
	if sigEnt.Signed.Signature.SanityCheck(ent.ID) != nil {
		logger.Error("RegisterEntity: invalid argument(s)",
			"signed_entity", sigEnt,
			"entity", ent,
		)
		return nil, ErrInvalidArgument
	}

	// Ensure the node list has no duplicates.
	nodesMap := make(map[signature.MapKey]bool)
	for _, v := range ent.Nodes {
		mk := v.ToMapKey()
		if nodesMap[mk] {
			logger.Error("RegisterEntity: duplicate entries in node list",
				"entity", ent,
			)
			return nil, ErrInvalidArgument
		}
		nodesMap[mk] = true
	}

	return &ent, nil
}

// VerifyDeregisterEntityArgs verifies arguments for DeregisterEntity.
func VerifyDeregisterEntityArgs(logger *logging.Logger, sigTimestamp *signature.Signed) (signature.PublicKey, uint64, error) {
	var id signature.PublicKey
	var timestamp Timestamp
	if sigTimestamp == nil {
		return nil, 0, ErrInvalidArgument
	}
	if err := sigTimestamp.Open(DeregisterEntitySignatureContext, &timestamp); err != nil {
		logger.Error("DeregisterEntity: invalid signature",
			"signed_timestamp", sigTimestamp,
		)
		return nil, 0, ErrInvalidSignature
	}
	id = sigTimestamp.Signature.PublicKey

	return id, uint64(timestamp), nil
}

// VerifyRegisterNodeArgs verifies arguments for RegisterNode.
func VerifyRegisterNodeArgs(logger *logging.Logger, sigNode *node.SignedNode, entity *entity.Entity, now time.Time, isGenesis bool) (*node.Node, error) {
	// XXX: Ensure node is well-formed.
	var n node.Node
	if sigNode == nil {
		return nil, ErrInvalidArgument
	}

	var ctx []byte
	switch isGenesis {
	case true:
		ctx = RegisterGenesisNodeSignatureContext
	case false:
		ctx = RegisterNodeSignatureContext
	}

	if err := sigNode.Open(ctx, &n); err != nil {
		logger.Error("RegisterNode: invalid signature",
			"signed_node", sigNode,
		)
		return nil, ErrInvalidSignature
	}

	// This should never happen, unless there's a bug in the caller.
	if !entity.ID.Equal(n.EntityID) {
		logger.Error("RegisterNode: node entity ID does not match expected entity",
			"node", n,
			"entity", entity,
		)
		return nil, ErrInvalidArgument
	}

	// Determine which key should be expected to have signed the node descriptor.
	var inEntityNodeList bool
	for _, v := range entity.Nodes {
		if n.ID.Equal(v) {
			inEntityNodeList = true
			break
		}
	}

	var expectedSigner signature.PublicKey
	if inEntityNodeList {
		expectedSigner = n.ID
	} else if entity.AllowEntitySignedNodes {
		expectedSigner = entity.ID
	} else {
		logger.Error("RegisterNode: node registration has no valid signer",
			"node", n,
			"entity", entity,
		)
		return nil, ErrInvalidArgument
	}

	// Validate that the node is signed by the correct signer.
	if sigNode.Signed.Signature.SanityCheck(expectedSigner) != nil {
		logger.Error("RegisterNode: not signed by expected signer",
			"signed_node", sigNode,
			"node", n,
			"entity", entity,
		)
		return nil, ErrInvalidArgument
	}

	// TODO: Key manager nodes maybe should be restricted to only being a
	// key manager at the expense of breaking some of our test configs.
	needRuntimes := n.HasRoles(node.RoleComputeWorker | node.RoleKeyManager) // XXX: RoleTransactionSceduler?

	switch len(n.Runtimes) {
	case 0:
		// TODO: This should be an registration failure, but the node registration
		// integration tests do the wrong thing.
		if needRuntimes {
			logger.Error("RegisterNode: no runtimes in registration",
				"node", n,
			)
		}
	default:
		rtMap := make(map[signature.MapKey]bool)

		// If the node indicates TEE support for any of it's runtimes,
		// validate the attestation evidence.
		for _, rt := range n.Runtimes {
			k := rt.ID.ToMapKey()
			if rtMap[k] {
				logger.Error("RegisterNode: duplicate runtime IDs",
					"id", rt.ID,
				)
				return nil, ErrInvalidArgument
			}
			rtMap[k] = true

			tee := rt.Capabilities.TEE
			if tee == nil {
				continue
			}

			if err := tee.Verify(now); err != nil {
				logger.Error("RegisterNode: failed to validate attestation",
					"node", n,
					"runtime", rt.ID,
					"err", err,
				)
				return nil, err
			}
		}
	}

	return &n, nil
}

// sortRuntimeList sorts the given runtime list to ensure a canonical order.
func sortRuntimeList(runtimes []*node.Runtime) {
	sort.Slice(runtimes, func(i, j int) bool {
		return bytes.Compare(runtimes[i].ID, runtimes[j].ID) == -1
	})
}

// verifyNodeRuntimeChanges verifies node runtime changes.
func verifyNodeRuntimeChanges(logger *logging.Logger, currentRuntimes []*node.Runtime, newRuntimes []*node.Runtime) bool {
	sortRuntimeList(currentRuntimes)
	sortRuntimeList(newRuntimes)
	if len(currentRuntimes) != len(newRuntimes) {
		logger.Error("RegisterNode: trying to update runtimes, length missmatch",
			"current_runtimes", currentRuntimes,
			"new_runtimes", newRuntimes,
		)
		return false
	}
	for i, currentRuntime := range currentRuntimes {
		newRuntime := newRuntimes[i]
		if !currentRuntime.ID.Equal(newRuntime.ID) {
			logger.Error("RegisterNode: trying to update runtimes, runtime ID changed",
				"current_runtime", currentRuntime,
				"new_runtime", newRuntime,
			)
			return false
		}
		if currentRuntime.Capabilities != newRuntime.Capabilities {
			logger.Error("RegisterNode: trying to update runtimes, runtime Capabilities changed",
				"current_runtime", currentRuntime,
				"new_runtime", newRuntime,
			)
			return false
		}
	}
	return true
}

// VerifyNodeUpdate verifies changes while updating the node.
func VerifyNodeUpdate(logger *logging.Logger, currentNode *node.Node, newNode *node.Node) error {
	// XXX: In future we might want to allow updating some of these fields as well. But these updates
	//      should only happen after the epoch transition.
	//      For now, node should un-register and re-register to update any of these fields.
	if !currentNode.ID.Equal(newNode.ID) {
		logger.Error("RegisterNode: trying to update node ID",
			"current_id", currentNode.ID.String(),
			"new_id", newNode.ID.String(),
		)
		return ErrNodeUpdateNotAllowed
	}
	if !currentNode.EntityID.Equal(newNode.EntityID) {
		logger.Error("RegisterNode: trying to update node entity ID",
			"current_id", currentNode.ID,
			"new_id", newNode.ID,
		)
		return ErrNodeUpdateNotAllowed
	}
	if !verifyNodeRuntimeChanges(logger, currentNode.Runtimes, newNode.Runtimes) {
		logger.Error("RegisterNode: trying to update node runtimes",
			"current_runtimes", currentNode.Runtimes,
			"new_runtimes", newNode.Runtimes,
		)
		return ErrNodeUpdateNotAllowed
	}
	if currentNode.Roles != newNode.Roles {
		logger.Error("RegisterNode: trying to update node roles",
			"current_roles", currentNode.Roles,
			"new_roles", newNode.Roles,
		)
		return ErrNodeUpdateNotAllowed
	}
	if currentNode.RegistrationTime >= newNode.RegistrationTime {
		logger.Error("RegisterNode: current node registration time greater than new",
			"current_registration_time", currentNode.RegistrationTime,
			"new_registration_time", newNode.RegistrationTime,
		)
		return ErrNodeUpdateNotAllowed
	}

	return nil
}

// VerifyRegisterRuntimeArgs verifies arguments for RegisterRuntime.
func VerifyRegisterRuntimeArgs(logger *logging.Logger, sigRt *SignedRuntime, isGenesis bool) (*Runtime, error) {
	// XXX: Ensure runtime is well-formed.
	var rt Runtime
	if sigRt == nil {
		return nil, ErrInvalidArgument
	}

	var ctx []byte
	switch isGenesis {
	case true:
		ctx = RegisterGenesisRuntimeSignatureContext
	case false:
		ctx = RegisterRuntimeSignatureContext
	}

	if err := sigRt.Open(ctx, &rt); err != nil {
		logger.Error("RegisterRuntime: invalid signature",
			"signed_runtime", sigRt,
		)
		return nil, ErrInvalidSignature
	}

	// TODO: Who should sign the runtime? Current compute node assumes an entity (deployer).
	switch rt.Kind {
	case KindCompute:
		if rt.ID.Equal(rt.KeyManager) {
			return nil, ErrInvalidArgument
		}
	case KindKeyManager:
		if !rt.ID.Equal(rt.KeyManager) {
			return nil, ErrInvalidArgument
		}
	default:
		return nil, ErrInvalidArgument
	}

	if !isGenesis && !rt.Genesis.StateRoot.IsEmpty() {
		// TODO: Verify storage receipt for the state root, reject such registrations for now.
		return nil, ErrInvalidArgument
	}

	return &rt, nil
}

// SortNodeList sorts the given node list to ensure a canonical order.
func SortNodeList(nodes []*node.Node) {
	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i].ID, nodes[j].ID) == -1
	})
}

// VerifyTimestamp verifies that the given timestamp is valid.
func VerifyTimestamp(timestamp uint64, now uint64) error {
	// For now, we check that it's new enough and not too far in the future.
	// We allow the timestamp to be up to 1 minute in the future to account
	// for network latency, leap seconds, and real-time clock inaccuracies
	// and drift.
	if timestamp < now-TimestampValidFor || timestamp > now+60 {
		return ErrInvalidTimestamp
	}

	return nil
}

// Genesis is the registry genesis state.
type Genesis struct {
	// Entities is the initial list of entities.
	Entities []*entity.SignedEntity `codec:"entities,omit_empty"`

	// Runtimes is the initial list of runtimes.
	Runtimes []*SignedRuntime `codec:"runtimes,omit_empty"`

	// Nodes is the initial list of nodes.
	Nodes []*node.SignedNode `codec:"nodes,omit_empty"`
}

// Config is the per-backend common configuration.
type Config struct {
	// DebugAllowRuntimeRegistration is true iff runtime registration should be
	// allowed outside of the genesis block.
	DebugAllowRuntimeRegistration bool

	// DebugBypassStake is true iff the registry should bypass all of the staking
	// related checks and operations.
	DebugBypassStake bool
}
