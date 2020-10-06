// Package api implements the runtime and entity registry APIs.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// ModuleName is a unique module name for the registry module.
const ModuleName = "registry"

var (
	// RegisterEntitySignatureContext is the context used for entity
	// registration.
	RegisterEntitySignatureContext = signature.NewContext("oasis-core/registry: register entity")

	// RegisterGenesisEntitySignatureContext is the context used for
	// entity registration in the genesis document.
	//
	// Note: This is identical to non-gensis registrations to support
	// migrating existing registrations into a new genesis document.
	RegisterGenesisEntitySignatureContext = RegisterEntitySignatureContext

	// RegisterNodeSignatureContext is the context used for node
	// registration.
	RegisterNodeSignatureContext = signature.NewContext("oasis-core/registry: register node")

	// RegisterGenesisNodeSignatureContext is the context used for
	// node registration in the genesis document.
	//
	// Note: This is identical to non-gensis registrations to support
	// migrating existing registrations into a new genesis document.
	RegisterGenesisNodeSignatureContext = RegisterNodeSignatureContext

	// RegisterRuntimeSignatureContext is the context used for runtime
	// registration.
	RegisterRuntimeSignatureContext = signature.NewContext("oasis-core/registry: register runtime")

	// RegisterGenesisRuntimeSignatureContext is the context used for
	// runtime registation in the genesis document.
	//
	// Note: This is identical to non-gensis registrations to support
	// migrating existing registrations into a new genesis document.
	RegisterGenesisRuntimeSignatureContext = RegisterRuntimeSignatureContext

	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New(ModuleName, 1, "registry: invalid argument")

	// ErrInvalidSignature is the error returned on an invalid signature.
	ErrInvalidSignature = errors.New(ModuleName, 2, "registry: invalid signature")

	// ErrBadEntityForNode is the error returned when a node registration
	// with an unknown entity is attempted.
	ErrBadEntityForNode = errors.New(ModuleName, 3, "registry: unknown entity in node registration")

	// ErrBadEntityForRuntime is the error returned when a runtime
	// attempts to register with an unknown entity.
	ErrBadEntityForRuntime = errors.New(ModuleName, 4, "registry: unknown entity in runtime registration")

	// ErrNoEnclaveForRuntime is the error returned when a TEE runtime
	// registers with no enclave IDs.
	ErrNoEnclaveForRuntime = errors.New(ModuleName, 5, "registry: no enclaves for TEE runtime registration")

	// ErrBadEnclaveIdentity is the error returned when a node tries to
	// register runtimes with wrong Enclave IDs.
	ErrBadEnclaveIdentity = errors.New(ModuleName, 6, "registry: bad enclave id")

	// ErrBadCapabilitiesTEEHardware is the error returned when a node tries to
	// register a runtime with bad Capabilities.TEE.Hardware.
	ErrBadCapabilitiesTEEHardware = errors.New(ModuleName, 7, "registry: bad capabilities.TEE.Hardware")

	// ErrTEEHardwareMismatch is the error returned when a node tries to
	// register a runtime and Capabilities.TEE.Hardware mismatches the one in
	// the registry.
	ErrTEEHardwareMismatch = errors.New(ModuleName, 8, "registry: runtime TEE.Hardware mismatches the one in registry")

	// ErrNoSuchEntity is the error returned when an entity does not exist.
	ErrNoSuchEntity = errors.New(ModuleName, 9, "registry: no such entity")

	// ErrNoSuchNode is the error returned when an node does not exist.
	ErrNoSuchNode = errors.New(ModuleName, 10, "registry: no such node")

	// ErrNoSuchRuntime is the error returned when an runtime does not exist.
	ErrNoSuchRuntime = errors.New(ModuleName, 11, "registry: no such runtime")

	// ErrIncorrectTxSigner is the error returned when the signer of the transaction
	// is not the correct one.
	ErrIncorrectTxSigner = errors.New(ModuleName, 12, "registry: incorrect tx signer")

	// ErrNodeExpired is the error returned when a node is expired.
	ErrNodeExpired = errors.New(ModuleName, 13, "registry: node expired")

	// ErrNodeCannotBeUnfrozen is the error returned when a node cannot yet be
	// unfrozen due to the freeze period not being over yet.
	ErrNodeCannotBeUnfrozen = errors.New(ModuleName, 14, "registry: node cannot be unfrozen yet")

	// ErrEntityHasNodes is the error returned when an entity cannot be deregistered
	// as it still has nodes.
	ErrEntityHasNodes = errors.New(ModuleName, 15, "registry: entity still has nodes")

	// ErrForbidden is the error returned when an operation is forbidden by
	// policy.
	ErrForbidden = errors.New(ModuleName, 16, "registry: forbidden by policy")

	// ErrNodeUpdateNotAllowed is the error returned when trying to update an existing node with
	// disallowed changes.
	ErrNodeUpdateNotAllowed = errors.New(ModuleName, 17, "registry: node update not allowed")

	// ErrRuntimeUpdateNotAllowed is the error returned when trying to update an existing runtime.
	ErrRuntimeUpdateNotAllowed = errors.New(ModuleName, 18, "registry: runtime update not allowed")

	// ErrEntityHasRuntimes is the error returned when an entity cannot be deregistered as it still
	// has runtimes.
	ErrEntityHasRuntimes = errors.New(ModuleName, 19, "registry: entity still has runtimes")

	// MethodRegisterEntity is the method name for entity registrations.
	MethodRegisterEntity = transaction.NewMethodName(ModuleName, "RegisterEntity", entity.SignedEntity{})
	// MethodDeregisterEntity is the method name for entity deregistrations.
	MethodDeregisterEntity = transaction.NewMethodName(ModuleName, "DeregisterEntity", nil)
	// MethodRegisterNode is the method name for node registrations.
	MethodRegisterNode = transaction.NewMethodName(ModuleName, "RegisterNode", node.MultiSignedNode{})
	// MethodUnfreezeNode is the method name for unfreezing nodes.
	MethodUnfreezeNode = transaction.NewMethodName(ModuleName, "UnfreezeNode", UnfreezeNode{})
	// MethodRegisterRuntime is the method name for registering runtimes.
	MethodRegisterRuntime = transaction.NewMethodName(ModuleName, "RegisterRuntime", SignedRuntime{})

	// Methods is the list of all methods supported by the registry backend.
	Methods = []transaction.MethodName{
		MethodRegisterEntity,
		MethodDeregisterEntity,
		MethodRegisterNode,
		MethodUnfreezeNode,
		MethodRegisterRuntime,
	}

	// RuntimesRequiredRoles are the Node roles that require runtimes.
	RuntimesRequiredRoles = node.RoleComputeWorker |
		node.RoleStorageWorker |
		node.RoleKeyManager

	// ComputeRuntimeAllowedRoles are the Node roles that allow compute runtimes.
	ComputeRuntimeAllowedRoles = node.RoleComputeWorker |
		node.RoleStorageWorker

	// KeyManagerRuntimeAllowedRoles are the Node roles that allow key manager runtimes.
	KeyManagerRuntimeAllowedRoles = node.RoleKeyManager

	// ConsensusAddressRequiredRoles are the Node roles that require Consensus Address.
	ConsensusAddressRequiredRoles = node.RoleValidator

	// TLSAddressRequiredRoles are the Node roles that require TLS Address.
	TLSAddressRequiredRoles = node.RoleComputeWorker |
		node.RoleStorageWorker |
		node.RoleKeyManager |
		node.RoleConsensusRPC

	// P2PAddressRequiredRoles are the Node roles that require P2P Address.
	P2PAddressRequiredRoles = node.RoleComputeWorker
)

// Backend is a registry implementation.
type Backend interface {
	// GetEntity gets an entity by ID.
	GetEntity(context.Context, *IDQuery) (*entity.Entity, error)

	// GetEntities gets a list of all registered entities.
	GetEntities(context.Context, int64) ([]*entity.Entity, error)

	// WatchEntities returns a channel that produces a stream of
	// EntityEvent on entity registration changes.
	WatchEntities(context.Context) (<-chan *EntityEvent, pubsub.ClosableSubscription, error)

	// GetNode gets a node by ID.
	GetNode(context.Context, *IDQuery) (*node.Node, error)

	// GetNodeStatus returns a node's status.
	GetNodeStatus(context.Context, *IDQuery) (*NodeStatus, error)

	// GetNodes gets a list of all registered nodes.
	GetNodes(context.Context, int64) ([]*node.Node, error)

	// GetNodeByConsensusAddress looks up a node by its consensus address at the
	// specified block height. The nature and format of the consensus address depends
	// on the specific consensus backend implementation used.
	GetNodeByConsensusAddress(context.Context, *ConsensusAddressQuery) (*node.Node, error)

	// WatchNodes returns a channel that produces a stream of
	// NodeEvent on node registration changes.
	WatchNodes(context.Context) (<-chan *NodeEvent, pubsub.ClosableSubscription, error)

	// WatchNodeList returns a channel that produces a stream of NodeList.
	// Upon subscription, the node list for the current epoch will be sent
	// immediately.
	//
	// Each node list will be sorted by node ID in lexicographically ascending
	// order.
	WatchNodeList(context.Context) (<-chan *NodeList, pubsub.ClosableSubscription, error)

	// GetRuntime gets a runtime by ID.
	GetRuntime(context.Context, *NamespaceQuery) (*Runtime, error)

	// GetRuntimes returns the registered Runtimes at the specified
	// block height.
	GetRuntimes(context.Context, *GetRuntimesQuery) ([]*Runtime, error)

	// WatchRuntimes returns a stream of Runtime.  Upon subscription,
	// all runtimes will be sent immediately.
	WatchRuntimes(context.Context) (<-chan *Runtime, pubsub.ClosableSubscription, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(context.Context, int64) (*Genesis, error)

	// GetEvents returns the events at specified block height.
	GetEvents(ctx context.Context, height int64) ([]*Event, error)

	// Cleanup cleans up the registry backend.
	Cleanup()
}

// IDQuery is a registry query by ID.
type IDQuery struct {
	Height int64               `json:"height"`
	ID     signature.PublicKey `json:"id"`
}

// NamespaceQuery is a registry query by namespace (Runtime ID).
type NamespaceQuery struct {
	Height int64            `json:"height"`
	ID     common.Namespace `json:"id"`
}

// GetRuntimesQuery is a registry get runtimes query.
type GetRuntimesQuery struct {
	Height           int64 `json:"height"`
	IncludeSuspended bool  `json:"include_suspended"`
}

// ConsensusAddressQuery is a registry query by consensus address.
// The nature and format of the consensus address depends on the specific
// consensus backend implementation used.
type ConsensusAddressQuery struct {
	Height  int64  `json:"height"`
	Address []byte `json:"address"`
}

// NewRegisterEntityTx creates a new register entity transaction.
func NewRegisterEntityTx(nonce uint64, fee *transaction.Fee, sigEnt *entity.SignedEntity) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodRegisterEntity, sigEnt)
}

// NewDeregisterEntityTx creates a new deregister entity transaction.
func NewDeregisterEntityTx(nonce uint64, fee *transaction.Fee) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodDeregisterEntity, nil)
}

// NewRegisterNodeTx creates a new register node transaction.
func NewRegisterNodeTx(nonce uint64, fee *transaction.Fee, sigNode *node.MultiSignedNode) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodRegisterNode, sigNode)
}

// NewUnfreezeNodeTx creates a new unfreeze node transaction.
func NewUnfreezeNodeTx(nonce uint64, fee *transaction.Fee, unfreeze *UnfreezeNode) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodUnfreezeNode, unfreeze)
}

// NewRegisterRuntimeTx creates a new register runtime transaction.
func NewRegisterRuntimeTx(nonce uint64, fee *transaction.Fee, sigRt *SignedRuntime) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodRegisterRuntime, sigRt)
}

// EntityEvent is the event that is returned via WatchEntities to signify
// entity registration changes and updates.
type EntityEvent struct {
	Entity         *entity.Entity `json:"entity"`
	IsRegistration bool           `json:"is_registration"`
}

// NodeEvent is the event that is returned via WatchNodes to signify node
// registration changes and updates.
type NodeEvent struct {
	Node           *node.Node `json:"node"`
	IsRegistration bool       `json:"is_registration"`
}

// RuntimeEvent signifies new runtime registration.
type RuntimeEvent struct {
	Runtime *Runtime `json:"runtime"`
}

// NodeUnfrozenEvent signifies when node becomes unfrozen.
type NodeUnfrozenEvent struct {
	NodeID signature.PublicKey `json:"node_id"`
}

// Event is a registry event returned via GetEvents.
type Event struct {
	Height int64     `json:"height,omitempty"`
	TxHash hash.Hash `json:"tx_hash,omitempty"`

	RuntimeEvent      *RuntimeEvent      `json:"runtime,omitempty"`
	EntityEvent       *EntityEvent       `json:"entity,omitempty"`
	NodeEvent         *NodeEvent         `json:"node,omitempty"`
	NodeUnfrozenEvent *NodeUnfrozenEvent `json:"node_unfrozen,omitempty"`
}

// NodeList is a per-epoch immutable node list.
type NodeList struct {
	Nodes []*node.Node `json:"nodes"`
}

// NodeLookup interface implements various ways for the verification
// functions to look-up nodes in the registry's state.
type NodeLookup interface {
	// NodeBySubKey looks up a specific node by its consensus, P2P or TLS key.
	NodeBySubKey(ctx context.Context, key signature.PublicKey) (*node.Node, error)

	// Returns a list of all nodes.
	Nodes(ctx context.Context) ([]*node.Node, error)
}

// RuntimeLookup interface implements various ways for the verification
// functions to look-up runtimes in the registry's state.
type RuntimeLookup interface {
	// Runtime looks up a runtime by its identifier and returns it.
	//
	// This excludes any suspended runtimes, use SuspendedRuntime to query suspended runtimes only.
	Runtime(ctx context.Context, id common.Namespace) (*Runtime, error)

	// SuspendedRuntime looks up a suspended runtime by its identifier and
	// returns it.
	SuspendedRuntime(ctx context.Context, id common.Namespace) (*Runtime, error)

	// AnyRuntime looks up either an active or suspended runtime by its identifier and returns it.
	AnyRuntime(ctx context.Context, id common.Namespace) (*Runtime, error)

	// AllRuntimes returns a list of all runtimes (including suspended ones).
	AllRuntimes(ctx context.Context) ([]*Runtime, error)
}

// VerifyRegisterEntityArgs verifies arguments for RegisterEntity.
func VerifyRegisterEntityArgs(logger *logging.Logger, sigEnt *entity.SignedEntity, isGenesis, isSanityCheck bool) (*entity.Entity, error) {
	var ent entity.Entity
	if sigEnt == nil {
		return nil, ErrInvalidArgument
	}

	var ctx signature.Context
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
	if err := sigEnt.Signed.Signature.SanityCheck(ent.ID); err != nil {
		logger.Error("RegisterEntity: invalid argument(s)",
			"signed_entity", sigEnt,
			"entity", ent,
			"err", err,
		)
		return nil, ErrInvalidArgument
	}
	if err := ent.ValidateBasic(!isGenesis && !isSanityCheck); err != nil {
		logger.Error("RegisterEntity: invalid entity descriptor",
			"entity", ent,
			"err", err,
		)
		return nil, ErrInvalidArgument
	}

	// Ensure the node list has no duplicates.
	nodesMap := make(map[signature.PublicKey]bool)
	for _, v := range ent.Nodes {
		if !v.IsValid() {
			logger.Error("RegisterEntity: malformed node id",
				"entity", ent,
			)
			return nil, fmt.Errorf("%w: malformed node id", ErrInvalidArgument)
		}

		if nodesMap[v] {
			logger.Error("RegisterEntity: duplicate entries in node list",
				"entity", ent,
			)
			return nil, fmt.Errorf("%w: duplicate nodes", ErrInvalidArgument)
		}
		nodesMap[v] = true
	}

	return &ent, nil
}

// VerifyRegisterNodeArgs verifies arguments for RegisterNode.
//
// Returns the node descriptor and a list of runtime descriptors the node is registering for.
func VerifyRegisterNodeArgs( // nolint: gocyclo
	ctx context.Context,
	params *ConsensusParameters,
	logger *logging.Logger,
	sigNode *node.MultiSignedNode,
	entity *entity.Entity,
	now time.Time,
	isGenesis bool,
	isSanityCheck bool,
	epoch epochtime.EpochTime,
	runtimeLookup RuntimeLookup,
	nodeLookup NodeLookup,
) (*node.Node, []*Runtime, error) {
	var n node.Node
	if sigNode == nil {
		return nil, nil, ErrInvalidArgument
	}

	var sigCtx signature.Context
	switch isGenesis {
	case true:
		sigCtx = RegisterGenesisNodeSignatureContext
	case false:
		sigCtx = RegisterNodeSignatureContext
	}

	if err := sigNode.Open(sigCtx, &n); err != nil {
		logger.Error("RegisterNode: invalid signature",
			"signed_node", sigNode,
		)
		return nil, nil, ErrInvalidSignature
	}
	if err := n.ValidateBasic(!isGenesis && !isSanityCheck); err != nil {
		logger.Error("RegisterNode: invalid node descriptor",
			"node", n,
			"err", err,
		)
		return nil, nil, ErrInvalidArgument
	}

	// This should never happen, unless there's a bug in the caller.
	if !entity.ID.Equal(n.EntityID) {
		logger.Error("RegisterNode: node entity ID does not match expected entity",
			"node", n,
			"entity", entity,
		)
		return nil, nil, ErrInvalidArgument
	}

	// Determine which key should be expected to have signed the node descriptor.
	var inEntityNodeList bool
	for _, v := range entity.Nodes {
		if n.ID.Equal(v) {
			inEntityNodeList = true
			break
		}
	}

	// Descriptors will always be signed by the node identity key.
	var expectedSigners []signature.PublicKey
	if !sigNode.MultiSigned.IsSignedBy(n.ID) {
		logger.Error("RegisterNode: registration not signed by node identity",
			"signed_node", sigNode,
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: registration not signed by node identity", ErrInvalidArgument)
	}
	expectedSigners = append(expectedSigners, n.ID)
	if !inEntityNodeList {
		// Entity signing node registrations is feature-gated by a consensus
		// parameter, and a per-entity configuration option.
		if !params.DebugAllowEntitySignedNodeRegistration || !entity.AllowEntitySignedNodes {
			logger.Error("RegisterNode: registration likely signed by entity",
				"signed_node", sigNode,
				"node", n,
			)
			return nil, nil, fmt.Errorf("%w: registration likely signed by entity", ErrInvalidArgument)
		}

		// If we are using entity signing, descriptors will also be signed
		// by the entity signing key.
		if !sigNode.MultiSigned.IsSignedBy(entity.ID) {
			logger.Error("RegisterNode: registration not signed by entity",
				"signed_node", sigNode,
				"node", n,
			)
			return nil, nil, fmt.Errorf("%w: registration not signed by entity", ErrInvalidArgument)
		}
		expectedSigners = append(expectedSigners, entity.ID)
	}

	// Expired registrations are allowed here because this routine is abused
	// by the invariant checker, and expired registrations are persisted in
	// the consensus state.

	// Ensure valid expiration.
	maxExpiration := uint64(epoch) + params.MaxNodeExpiration
	if params.MaxNodeExpiration > 0 && n.Expiration > maxExpiration {
		logger.Error("RegisterNode: node expiration greater than max allowed expiration",
			"node", n,
			"node_expiration", n.Expiration,
			"max_expiration", maxExpiration,
		)
		return nil, nil, fmt.Errorf("%w: expiration period greater than allowed", ErrInvalidArgument)
	}

	// Make sure that a node has at least one valid role.
	switch {
	case n.Roles == 0:
		logger.Error("RegisterNode: no roles specified",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: no roles specified", ErrInvalidArgument)
	case n.HasRoles(node.RoleReserved):
		logger.Error("RegisterNode: invalid role specified",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: invalid role specified", ErrInvalidArgument)
	}

	// TODO: Key manager nodes maybe should be restricted to only being a
	// key manager at the expense of breaking some of our test configs.

	var runtimes []*Runtime
	switch len(n.Runtimes) {
	case 0:
		if n.HasRoles(RuntimesRequiredRoles) {
			logger.Error("RegisterNode: no runtimes in registration",
				"node", n,
			)
			return nil, nil, fmt.Errorf("%w: missing runtimes", ErrInvalidArgument)
		}
	default:
		rtMap := make(map[common.Namespace]bool)

		for _, rt := range n.Runtimes {
			if rtMap[rt.ID] {
				logger.Error("RegisterNode: duplicate runtime IDs",
					"runtime_id", rt.ID,
				)
				return nil, nil, fmt.Errorf("%w: duplicate runtime IDs", ErrInvalidArgument)
			}
			rtMap[rt.ID] = true

			// Make sure that the claimed runtime actually exists.
			regRt, err := runtimeLookup.AnyRuntime(ctx, rt.ID)
			if err != nil {
				logger.Error("RegisterNode: failed to fetch supported runtime",
					"err", err,
					"runtime_id", rt.ID,
				)
				return nil, nil, fmt.Errorf("failed to lookup runtime: %w", err)
			}

			// If the node indicates TEE support for any of it's runtimes,
			// validate the attestation evidence.
			if err := VerifyNodeRuntimeEnclaveIDs(logger, rt, regRt, now); err != nil {
				return nil, nil, err
			}

			// Enforce what kinds of runtimes are allowed.
			if regRt.Kind == KindKeyManager && !n.HasRoles(KeyManagerRuntimeAllowedRoles) {
				return nil, nil, fmt.Errorf("%w: key manager runtime not allowed", ErrInvalidArgument)
			}
			if regRt.Kind == KindCompute && !n.HasRoles(ComputeRuntimeAllowedRoles) {
				return nil, nil, fmt.Errorf("%w: compute runtime not allowed", ErrInvalidArgument)
			}

			runtimes = append(runtimes, regRt)
		}
	}

	// Validate ConsensusInfo.
	if !n.Consensus.ID.IsValid() {
		logger.Error("RegisterNode: invalid consensus ID",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: invalid consensus ID", ErrInvalidArgument)
	}
	if !sigNode.MultiSigned.IsSignedBy(n.Consensus.ID) {
		logger.Error("RegisterNode: not signed by consensus ID",
			"signed_node", sigNode,
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: registration not signed by consensus ID", ErrInvalidArgument)
	}
	expectedSigners = append(expectedSigners, n.Consensus.ID)
	consensusAddressRequired := n.HasRoles(ConsensusAddressRequiredRoles)
	if err := verifyAddresses(params, consensusAddressRequired, n.Consensus.Addresses); err != nil {
		addrs, _ := json.Marshal(n.Consensus.Addresses)
		logger.Error("RegisterNode: missing/invalid consensus addresses",
			"node", n,
			"consensus_addrs", addrs,
		)
		return nil, nil, err
	}

	// Validate TLSInfo.
	if !n.TLS.PubKey.IsValid() {
		logger.Error("RegisterNode: invalid TLS public key",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: invalid TLS public key", ErrInvalidArgument)
	}
	tlsAddressRequired := n.HasRoles(TLSAddressRequiredRoles)
	if err := verifyAddresses(params, tlsAddressRequired, n.TLS.Addresses); err != nil {
		addrs, _ := json.Marshal(n.TLS.Addresses)
		logger.Error("RegisterNode: missing/invalid committee addresses",
			"node", n,
			"committee_addrs", addrs,
		)
		return nil, nil, err
	}

	if !sigNode.MultiSigned.IsSignedBy(n.TLS.PubKey) {
		logger.Error("RegisterNode: not signed by TLS certificate key",
			"signed_node", sigNode,
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: registration not signed by TLS certificate key", ErrInvalidArgument)
	}
	expectedSigners = append(expectedSigners, n.TLS.PubKey)

	// Validate P2PInfo.
	if !n.P2P.ID.IsValid() {
		logger.Error("RegisterNode: invalid P2P ID",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: invalid P2P ID", ErrInvalidArgument)
	}
	if !sigNode.MultiSigned.IsSignedBy(n.P2P.ID) {
		logger.Error("RegisterNode: not signed by P2P ID",
			"signed_node", sigNode,
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: registration not signed by P2P ID", ErrInvalidArgument)
	}
	expectedSigners = append(expectedSigners, n.P2P.ID)
	p2pAddressRequired := n.HasRoles(P2PAddressRequiredRoles)
	if err := verifyAddresses(params, p2pAddressRequired, n.P2P.Addresses); err != nil {
		addrs, _ := json.Marshal(n.P2P.Addresses)
		logger.Error("RegisterNode: missing/invald P2P addresses",
			"node", n,
			"p2p_addrs", addrs,
		)
		return nil, nil, err
	}

	// Make sure that the consensus, TLS and P2P keys are unique (between
	// themselves and compared to other nodes).
	//
	// Note that if a key exists and belongs to the same node ID, this is not
	// counted as an error, since it is possible that the node descriptor is
	// just being updated (this check is called in both cases).
	if n.Consensus.ID.Equal(n.P2P.ID) || n.Consensus.ID.Equal(n.TLS.PubKey) || n.P2P.ID.Equal(n.TLS.PubKey) {
		logger.Error("RegisterNode: node consensus, P2P and TLS keys must differ",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: P2P, consensus and TLS keys not unique", ErrInvalidArgument)
	}

	existingNode, err := nodeLookup.NodeBySubKey(ctx, n.Consensus.ID)
	if err != nil && err != ErrNoSuchNode {
		logger.Error("RegisterNode: failed to get node by consensus ID",
			"err", err,
			"consensus_id", n.Consensus.ID.String(),
		)
		return nil, nil, fmt.Errorf("failed to lookup node by subkey: %w", err)
	}
	if existingNode != nil && existingNode.ID != n.ID {
		logger.Error("RegisterNode: duplicate node consensus ID",
			"node_id", n.ID,
			"existing_node_id", existingNode.ID,
		)
		return nil, nil, fmt.Errorf("%w: duplicate node consensus ID", ErrInvalidArgument)
	}

	existingNode, err = nodeLookup.NodeBySubKey(ctx, n.P2P.ID)
	if err != nil && err != ErrNoSuchNode {
		logger.Error("RegisterNode: failed to get node by P2P ID",
			"err", err,
			"p2p_id", n.P2P.ID.String(),
		)
		return nil, nil, fmt.Errorf("failed to lookup node by subkey: %w", err)
	}
	if existingNode != nil && existingNode.ID != n.ID {
		logger.Error("RegisterNode: duplicate node P2P ID",
			"node_id", n.ID,
			"existing_node_id", existingNode.ID,
		)
		return nil, nil, fmt.Errorf("%w: duplicate node P2P ID", ErrInvalidArgument)
	}

	existingNode, err = nodeLookup.NodeBySubKey(ctx, n.TLS.PubKey)
	if err != nil && err != ErrNoSuchNode {
		logger.Error("RegisterNode: failed to get node by TLS public key",
			"err", err,
			"tls_pub_key", n.TLS.PubKey.String(),
		)
		return nil, nil, fmt.Errorf("failed to lookup node by subkey: %w", err)
	}
	if existingNode != nil && existingNode.ID != n.ID {
		logger.Error("RegisterNode: duplicate node TLS public key",
			"node_id", n.ID,
			"existing_node_id", existingNode.ID,
		)
		return nil, nil, fmt.Errorf("%w: duplicate node TLS public key", ErrInvalidArgument)
	}

	// Ensure that only the expected signatures are present, and nothing more.
	if !sigNode.MultiSigned.IsOnlySignedBy(expectedSigners) {
		logger.Error("RegisterNode: unexpected number of signatures",
			"signed_node", sigNode,
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: unexpected number of signatures", ErrInvalidArgument)
	}

	return &n, runtimes, nil
}

// VerifyNodeRuntimeEnclaveIDs verifies TEE-specific attributes of the node's runtime.
func VerifyNodeRuntimeEnclaveIDs(logger *logging.Logger, rt *node.Runtime, regRt *Runtime, ts time.Time) error {
	// If no TEE available, do nothing.
	if rt.Capabilities.TEE == nil {
		return nil
	}

	switch rt.Capabilities.TEE.Hardware {
	case node.TEEHardwareInvalid:
	case node.TEEHardwareIntelSGX:
		// Check MRENCLAVE/MRSIGNER.
		var avrBundle ias.AVRBundle
		if err := cbor.Unmarshal(rt.Capabilities.TEE.Attestation, &avrBundle); err != nil {
			return err
		}

		avr, err := avrBundle.Open(ias.IntelTrustRoots, ts)
		if err != nil {
			return err
		}

		// Extract the original ISV quote.
		q, err := avr.Quote()
		if err != nil {
			return err
		}

		if regRt.TEEHardware != rt.Capabilities.TEE.Hardware {
			logger.Error("VerifyNodeRuntimeEnclaveIDs: runtime TEE.Hardware mismatch",
				"quote", q,
				"node_runtime", rt,
				"registry_runtime", regRt,
				"ts", ts,
			)
			return ErrTEEHardwareMismatch
		}

		var vi VersionInfoIntelSGX
		if err := cbor.Unmarshal(regRt.Version.TEE, &vi); err != nil {
			return err
		}
		var eidValid bool
		for _, eid := range vi.Enclaves {
			eidMrenclave := eid.MrEnclave
			eidMrsigner := eid.MrSigner
			// Compare MRENCLAVE/MRSIGNER to the one stored in the registry.
			if bytes.Equal(eidMrenclave[:], q.Report.MRENCLAVE[:]) && bytes.Equal(eidMrsigner[:], q.Report.MRSIGNER[:]) {
				eidValid = true
				break
			}
		}

		if !eidValid {
			logger.Error("VerifyNodeRuntimeEnclaveIDs: bad enclave ID",
				"quote", q,
				"node_runtime", rt,
				"registry_runtime", regRt,
				"ts", ts,
			)
			return ErrBadEnclaveIdentity
		}
	default:
		return ErrBadCapabilitiesTEEHardware
	}

	if err := rt.Capabilities.TEE.Verify(ts); err != nil {
		logger.Error("VerifyNodeRuntimeEnclaveIDs: failed to validate attestation",
			"runtime_id", rt.ID,
			"ts", ts,
			"err", err,
		)
		return err
	}

	return nil
}

// VerifyAddress verifies a node address.
func VerifyAddress(addr node.Address, allowUnroutable bool) error {
	if !allowUnroutable {
		// Use the runtime to reject clearly invalid addresses.
		if !addr.IP.IsGlobalUnicast() {
			return fmt.Errorf("%w: address not global unicast", ErrInvalidArgument)
		}

		if !addr.IsRoutable() {
			return fmt.Errorf("%w: address not routable", ErrInvalidArgument)
		}
	}

	return nil
}

func verifyAddresses(params *ConsensusParameters, addressRequired bool, addresses interface{}) error {
	switch addrs := addresses.(type) {
	case []node.ConsensusAddress:
		if len(addrs) == 0 && addressRequired {
			return fmt.Errorf("%w: missing consensus address", ErrInvalidArgument)
		}
		for _, v := range addrs {
			if !v.ID.IsValid() {
				return fmt.Errorf("%w: consensus address ID invalid", ErrInvalidArgument)
			}
			if err := VerifyAddress(v.Address, params.DebugAllowUnroutableAddresses); err != nil {
				return err
			}
		}
	case []node.TLSAddress:
		if len(addrs) == 0 && addressRequired {
			return fmt.Errorf("%w: missing TLS address", ErrInvalidArgument)
		}
		for _, v := range addrs {
			if !v.PubKey.IsValid() {
				return fmt.Errorf("%w: TLS address public key invalid", ErrInvalidArgument)
			}
			if err := VerifyAddress(v.Address, params.DebugAllowUnroutableAddresses); err != nil {
				return err
			}
		}
	case []node.Address:
		if len(addrs) == 0 && addressRequired {
			return fmt.Errorf("%w: missing node address", ErrInvalidArgument)
		}
		for _, v := range addrs {
			if err := VerifyAddress(v, params.DebugAllowUnroutableAddresses); err != nil {
				return err
			}
		}
	default:
		panic(fmt.Sprintf("registry: unsupported addresses type: %T", addrs))
	}
	return nil
}

// verifyNodeRuntimeChanges verifies node runtime changes.
func verifyNodeRuntimeChanges(logger *logging.Logger, currentRuntimes, newRuntimes []*node.Runtime) bool {
	if len(newRuntimes) < len(currentRuntimes) {
		logger.Error("RegisterNode: trying to update runtimes, cannot remove existing runtimes",
			"current_runtimes", currentRuntimes,
			"new_runtimes", newRuntimes,
		)
		return false
	}

	// Make an index that maps runtime ID -> runtime, so we can do checks
	// faster.
	nrtMap := make(map[common.Namespace]*node.Runtime)
	for _, nrt := range newRuntimes {
		nrtMap[nrt.ID] = nrt
	}

	for _, currentRuntime := range currentRuntimes {
		newRuntime, exists := nrtMap[currentRuntime.ID]
		if !exists {
			logger.Error("RegisterNode: trying to update runtimes, current runtime is missing in new set",
				"runtime_id", currentRuntime.ID,
			)
			return false
		}
		if !verifyRuntimeCapabilities(logger, &currentRuntime.Capabilities, &newRuntime.Capabilities) {
			curRtJSON, _ := json.Marshal(currentRuntime)
			newRtJSON, _ := json.Marshal(newRuntime)
			logger.Error("RegisterNode: trying to update runtimes, runtime Capabilities changed",
				"current_runtime", curRtJSON,
				"new_runtime", newRtJSON,
			)
			return false
		}
	}
	return true
}

// verifyRuntimeCapabilities verifies node runtime capabilities changes.
func verifyRuntimeCapabilities(logger *logging.Logger, currentCaps, newCaps *node.Capabilities) bool {
	// TEE capability.
	if (currentCaps.TEE == nil) != (newCaps.TEE == nil) {
		logger.Error("RegisterNode: trying to change between TEE/non-TEE capability",
			"current_caps", currentCaps,
			"new_caps", newCaps,
		)
		return false
	}
	if currentCaps.TEE == nil {
		return true
	}
	if currentCaps.TEE.Hardware != newCaps.TEE.Hardware {
		logger.Error("RegisterNode: trying to change TEE hardware",
			"current_tee_hw", currentCaps.TEE.Hardware,
			"new_tee_hw", newCaps.TEE.Hardware,
		)
		return false
	}
	// RAK and Attestation fields are allowed to change as they may be updated if
	// the node and/or the runtime restarts.
	return true
}

// VerifyNodeUpdate verifies changes while updating the node.
func VerifyNodeUpdate(logger *logging.Logger, currentNode, newNode *node.Node) error {
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
			"current_id", currentNode.EntityID,
			"new_id", newNode.EntityID,
		)
		return ErrNodeUpdateNotAllowed
	}
	if !verifyNodeRuntimeChanges(logger, currentNode.Runtimes, newNode.Runtimes) {
		curNodeRuntimes, _ := json.Marshal(currentNode.Runtimes)
		newNodeRuntimes, _ := json.Marshal(newNode.Runtimes)
		logger.Error("RegisterNode: trying to update node runtimes",
			"current_runtimes", curNodeRuntimes,
			"new_runtimes", newNodeRuntimes,
		)
		return ErrNodeUpdateNotAllowed
	}
	if !newNode.HasRoles(currentNode.Roles) {
		// Allow nodes to increase the roles they wish to opt-in to,
		// but not to remove any roles.
		logger.Error("RegisterNode: trying to update node roles - downgrade",
			"current_roles", currentNode.Roles,
			"new_roles", newNode.Roles,
		)
		return ErrNodeUpdateNotAllowed
	}

	// Every node requires a Consensus.ID and it shouldn't be updated.
	if !currentNode.Consensus.ID.Equal(newNode.Consensus.ID) {
		logger.Error("RegisterNode: trying to update consensus ID",
			"current_id", currentNode.Consensus.ID,
			"new_id", newNode.Consensus.ID,
		)
		return ErrNodeUpdateNotAllowed
	}

	return nil
}

func exactlyOneTrue(conds ...bool) bool {
	total := 0
	for _, c := range conds {
		if c {
			total++
		}
	}
	return total == 1
}

// VerifyRegisterRuntimeArgs verifies arguments for RegisterRuntime.
func VerifyRegisterRuntimeArgs( // nolint: gocyclo
	params *ConsensusParameters,
	logger *logging.Logger,
	sigRt *SignedRuntime,
	isGenesis bool,
	isSanityCheck bool,
) (*Runtime, error) {
	var rt Runtime
	if sigRt == nil {
		return nil, ErrInvalidArgument
	}

	var ctx signature.Context
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
	if err := sigRt.Signed.Signature.SanityCheck(rt.EntityID); err != nil {
		logger.Error("RegisterRuntime: invalid argument(s)",
			"signed_runtime", sigRt,
			"runtime", rt,
			"err", err,
		)
		return nil, ErrInvalidArgument
	}
	if err := rt.ValidateBasic(!isGenesis && !isSanityCheck); err != nil {
		logger.Error("RegisterRuntime: invalid runtime descriptor",
			"runtime", rt,
			"err", err,
		)
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err)
	}

	if rt.ID.IsTest() && !params.DebugAllowTestRuntimes {
		logger.Error("RegisterRuntime: test runtime registration not allowed",
			"id", rt.ID,
		)
		return nil, fmt.Errorf("%w: test runtime not allowed", ErrInvalidArgument)
	}

	if err := rt.Genesis.SanityCheck(isGenesis); err != nil {
		return nil, err
	}

	// Ensure a valid TEE hardware is specified.
	if rt.TEEHardware >= node.TEEHardwareReserved {
		logger.Error("RegisterRuntime: invalid TEE hardware specified",
			"runtime", rt,
		)
		return nil, fmt.Errorf("%w: invalid TEE hardware", ErrInvalidArgument)
	}

	// If TEE is required, check if runtime provided at least one enclave ID.
	if rt.TEEHardware != node.TEEHardwareInvalid {
		switch rt.TEEHardware {
		case node.TEEHardwareIntelSGX:
			var vi VersionInfoIntelSGX
			if err := cbor.Unmarshal(rt.Version.TEE, &vi); err != nil {
				logger.Error("RegisterRuntime: invalid SGX TEE Version Info",
					"version_info", vi,
					"err", err,
				)
				return nil, fmt.Errorf("%w: invalid VersionInfo", ErrInvalidArgument)
			}
			if len(vi.Enclaves) == 0 {
				return nil, fmt.Errorf("%w: invalid VersionInfo", ErrNoEnclaveForRuntime)
			}
		}
	}

	// Ensure there's a valid admission policy.
	if !exactlyOneTrue(rt.AdmissionPolicy.AnyNode != nil, rt.AdmissionPolicy.EntityWhitelist != nil) {
		logger.Error("RegisterRuntime: invalid admission policy. exactly one policy should be non-nil",
			"admission_policy", rt.AdmissionPolicy,
		)
		return nil, fmt.Errorf("%w: invalid admission policy", ErrInvalidArgument)
	}

	return &rt, nil
}

// VerifyRegisterComputeRuntimeArgs verifies compute runtime-specific arguments for RegisterRuntime.
func VerifyRegisterComputeRuntimeArgs(ctx context.Context, logger *logging.Logger, rt *Runtime, runtimeLookup RuntimeLookup) error {
	// Check runtime's key manager, if key manager ID is set.
	if rt.KeyManager != nil {
		km, err := runtimeLookup.AnyRuntime(ctx, *rt.KeyManager)
		if err != nil {
			logger.Error("RegisterRuntime: error when fetching the runtime's key manager from registry",
				"runtime", rt.ID,
				"key_manager", rt.KeyManager,
			)
			return err
		}

		// Key manager runtime should be valid.
		if km.Kind != KindKeyManager {
			logger.Error("RegisterRuntime: provided key manager runtime is not key manager",
				"runtime", rt.ID,
				"key_manager", rt.KeyManager,
				"expected_kind", KindKeyManager,
				"actual_kind", km.Kind,
			)
			return ErrInvalidArgument
		}

		// Currently the keymanager implementation assumes SGX. Unless this is a
		// test runtime, using a keymanager without using SGX is unsupported.
		if !rt.ID.IsTest() && rt.TEEHardware != node.TEEHardwareIntelSGX {
			logger.Error("RegisterRuntime: runtime without SGX using key manager",
				"id", rt.ID,
			)
			return fmt.Errorf("%w: compute runtime without SGX using key manager", ErrInvalidArgument)
		}
	}

	return nil
}

// VerifyRuntimeUpdate verifies changes while updating the runtime.
func VerifyRuntimeUpdate(logger *logging.Logger, currentRt, newRt *Runtime) error {
	if !currentRt.EntityID.Equal(newRt.EntityID) {
		logger.Error("RegisterRuntime: trying to change runtime owner",
			"current_owner", currentRt.EntityID,
			"new_owner", newRt.EntityID,
		)
		return ErrRuntimeUpdateNotAllowed
	}
	if !currentRt.ID.Equal(&newRt.ID) {
		logger.Error("RegisterRuntime: trying to update runtime ID",
			"current_id", currentRt.ID.String(),
			"new_id", newRt.ID.String(),
		)
		return ErrRuntimeUpdateNotAllowed
	}
	if currentRt.Kind != newRt.Kind {
		logger.Error("RegisterRuntime: trying to update runtime kind",
			"current_kind", currentRt.Kind,
			"new_kind", newRt.Kind,
		)
		return ErrRuntimeUpdateNotAllowed
	}
	if !currentRt.Genesis.Equal(&newRt.Genesis) {
		logger.Error("RegisterRuntime: trying to update genesis")
		return ErrRuntimeUpdateNotAllowed
	}
	if (currentRt.KeyManager == nil) != (newRt.KeyManager == nil) {
		logger.Error("RegisterRuntime: trying to change key manager",
			"current_km", currentRt.KeyManager,
			"new_km", newRt.KeyManager,
		)
		return ErrRuntimeUpdateNotAllowed
	}
	// Both descriptors must either have the key manager set or not.
	if currentRt.KeyManager != nil && !currentRt.KeyManager.Equal(newRt.KeyManager) {
		logger.Error("RegisterRuntime: trying to change key manager",
			"current_km", currentRt.KeyManager,
			"new_km", newRt.KeyManager,
		)
		return ErrRuntimeUpdateNotAllowed
	}
	return nil
}

// SortNodeList sorts the given node list to ensure a canonical order.
func SortNodeList(nodes []*node.Node) {
	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i].ID[:], nodes[j].ID[:]) == -1
	})
}

// Genesis is the registry genesis state.
type Genesis struct {
	// Parameters are the registry consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// Entities is the initial list of entities.
	Entities []*entity.SignedEntity `json:"entities,omitempty"`

	// Runtimes is the initial list of runtimes.
	Runtimes []*SignedRuntime `json:"runtimes,omitempty"`
	// SuspendedRuntimes is the list of suspended runtimes.
	SuspendedRuntimes []*SignedRuntime `json:"suspended_runtimes,omitempty"`

	// Nodes is the initial list of nodes.
	Nodes []*node.MultiSignedNode `json:"nodes,omitempty"`

	// NodeStatuses is a set of node statuses.
	NodeStatuses map[signature.PublicKey]*NodeStatus `json:"node_statuses,omitempty"`
}

// ConsensusParameters are the registry consensus parameters.
type ConsensusParameters struct {
	// DebugAllowUnroutableAddresses is true iff node registration should
	// allow unroutable addreses.
	DebugAllowUnroutableAddresses bool `json:"debug_allow_unroutable_addresses,omitempty"`

	// DebugAllowTestRuntimes is true iff test runtimes should be allowed to
	// be registered.
	DebugAllowTestRuntimes bool `json:"debug_allow_test_runtimes,omitempty"`

	// DebugAllowEntitySignedNodeRegistration is true iff node registration
	// signed by entity signing keys should be allowed.
	DebugAllowEntitySignedNodeRegistration bool `json:"debug_allow_entity_signed_node_registration,omitempty"`

	// DebugBypassStake is true iff the registry should bypass all of the staking
	// related checks and operations.
	DebugBypassStake bool `json:"debug_bypass_stake,omitempty"`

	// DisableRuntimeRegistration is true iff runtime registration should be
	// disabled outside of the genesis block.
	DisableRuntimeRegistration bool `json:"disable_runtime_registration,omitempty"`

	// DisableRuntimeRegistration is true iff key manager runtime registration should be
	// disabled outside of the genesis block.
	DisableKeyManagerRuntimeRegistration bool `json:"disable_km_runtime_registration,omitempty"`

	// GasCosts are the registry transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// MaxNodeExpiration is the maximum number of epochs relative to the epoch
	// at registration time that a single node registration is valid for.
	MaxNodeExpiration uint64 `json:"max_node_expiration,omitempty"`
}

const (
	// GasOpRegisterEntity is the gas operation identifier for entity registration.
	GasOpRegisterEntity transaction.Op = "register_entity"
	// GasOpDeregisterEntity is the gas operation identifier for entity deregistration.
	GasOpDeregisterEntity transaction.Op = "deregister_entity"
	// GasOpRegisterNode is the gas operation identifier for entity registration.
	GasOpRegisterNode transaction.Op = "register_node"
	// GasOpUnfreezeNode is the gas operation identifier for unfreezing nodes.
	GasOpUnfreezeNode transaction.Op = "unfreeze_node"
	// GasOpRegisterRuntime is the gas operation identifier for runtime registration.
	GasOpRegisterRuntime transaction.Op = "register_runtime"
	// GasOpRuntimeEpochMaintenance is the gas operation identifier for per-epoch
	// runtime maintenance costs.
	GasOpRuntimeEpochMaintenance transaction.Op = "runtime_epoch_maintenance"
	// GasOpUpdateKeyManager is the gas operation identifier for key manager
	// policy updates costs.
	GasOpUpdateKeyManager transaction.Op = "update_keymanager"
)

// XXX: Define reasonable default gas costs.

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpRegisterEntity:          1000,
	GasOpDeregisterEntity:        1000,
	GasOpRegisterNode:            1000,
	GasOpUnfreezeNode:            1000,
	GasOpRegisterRuntime:         1000,
	GasOpRuntimeEpochMaintenance: 1000,
	GasOpUpdateKeyManager:        1000,
}

const (
	// StakeClaimRegisterEntity is the stake claim identifier used for registering an entity.
	StakeClaimRegisterEntity = "registry.RegisterEntity"
	// StakeClaimRegisterNode is the stake claim template used for registering nodes.
	StakeClaimRegisterNode = "registry.RegisterNode.%s"
	// StakeClaimRegisterRuntime is the stake claim template used for registering runtimes.
	StakeClaimRegisterRuntime = "registry.RegisterRuntime.%s"
)

// StakeClaimForNode generates a new stake claim identifier for a specific node registration.
func StakeClaimForNode(id signature.PublicKey) staking.StakeClaim {
	return staking.StakeClaim(fmt.Sprintf(StakeClaimRegisterNode, id))
}

// StakeClaimForRuntime generates a new stake claim for a specific runtime registration.
func StakeClaimForRuntime(id common.Namespace) staking.StakeClaim {
	return staking.StakeClaim(fmt.Sprintf(StakeClaimRegisterRuntime, id))
}

// StakeThresholdsForNode returns the staking thresholds for the given node.
//
// The passed list of runtimes must be runtime descriptors for all runtimes that the node is
// registered for in the same order as they appear in the node descriptor (for example as returned
// by the VerifyRegisterNodeArgs function).
func StakeThresholdsForNode(n *node.Node, rts []*Runtime) (thresholds []staking.StakeThreshold) {
	// Validator nodes are global.
	if n.HasRoles(node.RoleValidator) {
		thresholds = append(thresholds, staking.GlobalStakeThreshold(staking.KindNodeValidator))
	}

	// Add runtime-specific role thresholds for each registered runtime.
	for i, rt := range rts {
		if !n.Runtimes[i].ID.Equal(&rt.ID) {
			panic(fmt.Errorf("registry: mismatched runtime order"))
		}

		var roleThresholds []staking.ThresholdKind
		if n.HasRoles(node.RoleKeyManager) {
			roleThresholds = append(roleThresholds, staking.KindNodeKeyManager)
		}
		if n.HasRoles(node.RoleComputeWorker) {
			roleThresholds = append(roleThresholds, staking.KindNodeCompute)
		}
		if n.HasRoles(node.RoleStorageWorker) {
			roleThresholds = append(roleThresholds, staking.KindNodeStorage)
		}

		rtThresholds := rt.Staking.Thresholds
		for _, t := range roleThresholds {
			// Add global threshold.
			thresholds = append(thresholds, staking.GlobalStakeThreshold(t))
			// Add per-runtime threshold if non-zero.
			if q := rtThresholds[t]; !q.IsZero() {
				thresholds = append(thresholds, staking.StakeThreshold{Constant: q.Clone()})
			}
		}
	}
	return
}

// StakeThresholdsForRuntime returns the staking thresholds for the given runtime.
func StakeThresholdsForRuntime(rt *Runtime) (thresholds []staking.StakeThreshold) {
	switch rt.Kind {
	case KindCompute:
		thresholds = append(thresholds, staking.GlobalStakeThreshold(staking.KindRuntimeCompute))
	case KindKeyManager:
		thresholds = append(thresholds, staking.GlobalStakeThreshold(staking.KindRuntimeKeyManager))
	default:
		panic(fmt.Errorf("registry: unknown runtime kind: %s", rt.Kind))
	}
	return
}
