// Package api implements the runtime and entity registry APIs.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
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
	MethodDeregisterEntity = transaction.NewMethodName(ModuleName, "DeregisterEntity", DeregisterEntity{})
	// MethodRegisterNode is the method name for node registrations.
	MethodRegisterNode = transaction.NewMethodName(ModuleName, "RegisterNode", node.MultiSignedNode{})
	// MethodUnfreezeNode is the method name for unfreezing nodes.
	MethodUnfreezeNode = transaction.NewMethodName(ModuleName, "UnfreezeNode", UnfreezeNode{})
	// MethodRegisterRuntime is the method name for registering runtimes.
	MethodRegisterRuntime = transaction.NewMethodName(ModuleName, "RegisterRuntime", Runtime{})
	// MethodProveFreshness is the method name for freshness proofs.
	MethodProveFreshness = transaction.NewMethodName(ModuleName, "ProveFreshness", Runtime{})

	// Methods is the list of all methods supported by the registry backend.
	Methods = []transaction.MethodName{
		MethodRegisterEntity,
		MethodDeregisterEntity,
		MethodRegisterNode,
		MethodUnfreezeNode,
		MethodRegisterRuntime,
		MethodProveFreshness,
	}

	// RuntimesRequiredRoles are the Node roles that require runtimes.
	RuntimesRequiredRoles = node.RoleComputeWorker |
		node.RoleKeyManager |
		node.RoleStorageRPC

	// ComputeRuntimeAllowedRoles are the Node roles that allow compute runtimes.
	ComputeRuntimeAllowedRoles = node.RoleComputeWorker | node.RoleObserver

	// KeyManagerRuntimeAllowedRoles are the Node roles that allow key manager runtimes.
	KeyManagerRuntimeAllowedRoles = node.RoleKeyManager

	// ConsensusAddressRequiredRoles are the Node roles that require Consensus Address.
	ConsensusAddressRequiredRoles = node.RoleValidator

	// P2PAddressRequiredRoles are the Node roles that require P2P Address.
	P2PAddressRequiredRoles = node.RoleComputeWorker |
		node.RoleKeyManager |
		node.RoleValidator |
		node.RoleStorageRPC
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
	GetRuntime(context.Context, *GetRuntimeQuery) (*Runtime, error)

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

	// WatchEvents returns a channel that produces a stream of Events.
	WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error)

	// ConsensusParameters returns the registry consensus parameters.
	ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error)

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

// GetRuntimeQuery is a registry query by namespace (Runtime ID).
type GetRuntimeQuery struct {
	Height           int64            `json:"height"`
	ID               common.Namespace `json:"id"`
	IncludeSuspended bool             `json:"include_suspended,omitempty"`
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

// DeregisterEntity is a request to deregister an entity.
type DeregisterEntity struct{}

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
func NewRegisterRuntimeTx(nonce uint64, fee *transaction.Fee, rt *Runtime) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodRegisterRuntime, rt)
}

// NewProveFreshnessTx creates a new prove freshness transaction.
func NewProveFreshnessTx(nonce uint64, fee *transaction.Fee, blob [32]byte) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodProveFreshness, blob)
}

// EntityEvent is the event that is returned via WatchEntities to signify
// entity registration changes and updates.
type EntityEvent struct {
	Entity         *entity.Entity `json:"entity"`
	IsRegistration bool           `json:"is_registration"`
}

// EventKind returns a string representation of this event's kind.
func (e *EntityEvent) EventKind() string {
	return "entity"
}

// NodeEvent is the event that is returned via WatchNodes to signify node
// registration changes and updates.
type NodeEvent struct {
	Node           *node.Node `json:"node"`
	IsRegistration bool       `json:"is_registration"`
}

// EventKind returns a string representation of this event's kind.
func (e *NodeEvent) EventKind() string {
	return "node"
}

// RuntimeStartedEvent signifies a runtime started event.
//
// Emitted when a new runtime is started or a previously suspended runtime is resumed.
type RuntimeStartedEvent struct {
	Runtime *Runtime `json:"runtime"`
}

// EventKind returns a string representation of this event's kind.
func (e *RuntimeStartedEvent) EventKind() string {
	return "runtime_started"
}

// RuntimeSuspendedEvent signifies a runtime was suspended.
type RuntimeSuspendedEvent struct {
	RuntimeID common.Namespace `json:"runtime_id"`
}

// EventKind returns a string representation of this event's kind.
func (e *RuntimeSuspendedEvent) EventKind() string {
	return "runtime_suspended"
}

// NodeUnfrozenEvent signifies when node becomes unfrozen.
type NodeUnfrozenEvent struct {
	NodeID signature.PublicKey `json:"node_id"`
}

// EventKind returns a string representation of this event's kind.
func (e *NodeUnfrozenEvent) EventKind() string {
	return "node_unfrozen"
}

var _ events.CustomTypedAttribute = (*NodeListEpochEvent)(nil)

// NodeListEpochEvent is the per epoch node list event.
type NodeListEpochEvent struct{}

// EventKind returns a string representation of this event's kind.
func (e *NodeListEpochEvent) EventKind() string {
	return "node_list_epoch"
}

// EventValue returns a string representation of this event's kind.
func (e *NodeListEpochEvent) EventValue() string {
	// Dummy value, should be ignored.
	return "1"
}

// DecodeValue decodes the attribute event value.
func (e *NodeListEpochEvent) DecodeValue(string) error {
	return nil
}

// Event is a registry event returned via GetEvents.
type Event struct {
	Height int64     `json:"height,omitempty"`
	TxHash hash.Hash `json:"tx_hash,omitempty"`

	RuntimeStartedEvent   *RuntimeStartedEvent   `json:"runtime_started,omitempty"`
	RuntimeSuspendedEvent *RuntimeSuspendedEvent `json:"runtime_suspended,omitempty"`
	EntityEvent           *EntityEvent           `json:"entity,omitempty"`
	NodeEvent             *NodeEvent             `json:"node,omitempty"`
	NodeUnfrozenEvent     *NodeUnfrozenEvent     `json:"node_unfrozen,omitempty"`
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

	// Nodes returns a list of all registered nodes.
	Nodes(ctx context.Context) ([]*node.Node, error)

	// GetEntityNodes returns nodes registered by given entity.
	// Note that this returns both active and expired nodes.
	GetEntityNodes(ctx context.Context, id signature.PublicKey) ([]*node.Node, error)
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

	// Runtimes returns active runtimes (not including suspended ones).
	Runtimes(ctx context.Context) ([]*Runtime, error)
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
	height uint64,
	isGenesis bool,
	isSanityCheck bool,
	epoch beacon.EpochTime,
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

	// Descriptors will always be signed by the node identity key.
	var expectedSigners []signature.PublicKey
	if !sigNode.MultiSigned.IsSignedBy(n.ID) {
		logger.Debug("RegisterNode: registration not signed by node identity",
			"signed_node", sigNode,
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: registration not signed by node identity", ErrInvalidArgument)
	}
	expectedSigners = append(expectedSigners, n.ID)
	if !entity.HasNode(n.ID) && (!isSanityCheck || isGenesis) {
		logger.Debug("RegisterNode: node public key not found in entity's node list",
			"signed_node", sigNode,
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: node public key not found in entity's node list", ErrInvalidArgument)
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
		rtMap := make(map[common.Namespace]*Runtime)
		rtVersionMap := make(map[common.Namespace]map[version.Version]bool)

		for _, rt := range n.Runtimes {
			// Ensure no nil runtime.
			if rt == nil {
				return nil, nil, ErrInvalidArgument
			}
			if rtVersionMap[rt.ID] == nil {
				rtVersionMap[rt.ID] = make(map[version.Version]bool)
			}
			if rtVersionMap[rt.ID][rt.Version] {
				logger.Error("RegisterNode: duplicate version for runtime",
					"runtime_id", rt.ID,
					"runtime_version", rt.Version,
				)
				return nil, nil, fmt.Errorf("%w: duplicate version for runtime", ErrInvalidArgument)

			}
			rtVersionMap[rt.ID][rt.Version] = true

			// Make sure that the claimed runtime actually exists.
			regRt, err := runtimeLookup.AnyRuntime(ctx, rt.ID)
			if err != nil {
				logger.Error("RegisterNode: failed to fetch supported runtime",
					"err", err,
					"runtime_id", rt.ID,
				)
				return nil, nil, fmt.Errorf("failed to lookup runtime: %w", err)
			}

			// If the node indicates TEE support for any of it's runtimes, validate the attestation
			// evidence.
			//
			// These checks are skipped at time of genesis as there can be nodes present which are
			// both validators and compute nodes and have out of date attestation evidence. Removing
			// such nodes could lead to consensus not having the proper majority. This is safe as
			// attestation evidence is independently verified before scheduling committees.
			if err := VerifyNodeRuntimeEnclaveIDs(logger, n.ID, rt, regRt, params.TEEFeatures, now, height); err != nil && !isSanityCheck && !isGenesis {
				return nil, nil, err
			}

			// Enforce what kinds of runtimes are allowed.
			if regRt.Kind == KindKeyManager && !n.HasRoles(KeyManagerRuntimeAllowedRoles) {
				return nil, nil, fmt.Errorf("%w: key manager runtime not allowed", ErrInvalidArgument)
			}
			if regRt.Kind == KindCompute && !n.HasRoles(ComputeRuntimeAllowedRoles) {
				return nil, nil, fmt.Errorf("%w: compute runtime not allowed", ErrInvalidArgument)
			}

			// Append to the list of runtimes once and only once.
			if rtMap[rt.ID] == nil {
				rtMap[rt.ID] = regRt
				runtimes = append(runtimes, regRt)
			}
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

	// Validate VRFInfo.
	if !n.VRF.ID.IsValid() {
		logger.Error("RegisterNode: invalid VRF ID",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: invalid VRF ID", ErrInvalidArgument)
	}
	if !sigNode.MultiSigned.IsSignedBy(n.VRF.ID) {
		logger.Error("RegisterNode: not signed by VRF ID",
			"signed_node", sigNode,
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: registration not signed by VRF ID", ErrInvalidArgument)
	}
	expectedSigners = append(expectedSigners, n.VRF.ID)

	// Validate TLSInfo.
	if !n.TLS.PubKey.IsValid() {
		logger.Error("RegisterNode: invalid TLS public key",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: invalid TLS public key", ErrInvalidArgument)
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
	switch isGenesis || isSanityCheck {
	case true:
		// Allow legacy descriptor with optional p2p address for validator.
		// XXX: Remove this after 23.0.x.
		if n.HasRoles(node.RoleValidator) {
			p2pAddressRequired = false
		}
	case false:
		// All new (re)registrations will require a p2p address for all nodes,
		// and will reject descriptors otherwise.
	}

	if err := verifyAddresses(params, p2pAddressRequired, n.P2P.Addresses); err != nil {
		addrs, _ := json.Marshal(n.P2P.Addresses)
		logger.Error("RegisterNode: missing/invalid P2P addresses",
			"node", n,
			"p2p_addrs", addrs,
		)
		return nil, nil, err
	}

	// Make sure that the consensus, TLS, P2P, and VRF keys are unique
	// (between themselves and compared to other nodes).
	//
	// Note that if a key exists and belongs to the same node ID, this is not
	// counted as an error, since it is possible that the node descriptor is
	// just being updated (this check is called in both cases).
	type nodeSubKey struct {
		descr string
		id    signature.PublicKey
	}

	subKeyDedup := make(map[signature.PublicKey]bool)
	subKeys := []nodeSubKey{
		{"consensus ID", n.Consensus.ID},
		{"P2P ID", n.P2P.ID},
		{"TLS public key", n.TLS.PubKey},
		{"VRF ID", n.VRF.ID},
	}

	for _, subKey := range subKeys {
		subKeyDedup[subKey.id] = true

		existingNode, err := nodeLookup.NodeBySubKey(ctx, subKey.id)
		if err != nil && err != ErrNoSuchNode {
			logger.Error(fmt.Sprintf("RegisterNode: failed to get node by %s", subKey.descr),
				"err", err,
				"subkey_id", subKey.id.String(),
			)
		}

		if existingNode != nil && existingNode.ID != n.ID {
			logger.Error(fmt.Sprintf("RegisterNode: duplicate node %s", subKey.descr),
				"node_id", n.ID,
				"existing_node_id", existingNode.ID,
			)
			return nil, nil, fmt.Errorf("%w: duplicate node %s", ErrInvalidArgument, subKey.descr)
		}
	}

	if len(subKeyDedup) != len(subKeys) {
		logger.Error("RegisterNode: node consensus, P2P, VRF and TLS keys must differ",
			"node", n,
		)
		return nil, nil, fmt.Errorf("%w: node consensus, P2P, VRF and TLS keys not unique", ErrInvalidArgument)
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
func VerifyNodeRuntimeEnclaveIDs(
	logger *logging.Logger,
	nodeID signature.PublicKey,
	rt *node.Runtime,
	regRt *Runtime,
	teeCfg *node.TEEFeatures,
	ts time.Time,
	height uint64,
) error {
	// Verify that the node is running on the same hardware as the runtime.
	hw := node.TEEHardwareInvalid
	if rt.Capabilities.TEE != nil {
		hw = rt.Capabilities.TEE.Hardware
	}
	if hw != regRt.TEEHardware {
		logger.Error("VerifyNodeRuntimeEnclaveIDs: runtime TEE.Hardware mismatch",
			"runtime_id", rt.ID,
			"required_tee_hardware", regRt.TEEHardware,
			"tee_hardware", hw,
			"ts", ts,
		)
		return ErrTEEHardwareMismatch
	}

	// If no TEE available, do nothing.
	if rt.Capabilities.TEE == nil {
		return nil
	}

	// Find the runtime in the descriptor corresponding to the version
	// that is to be validated.
	for _, rtVersionInfo := range regRt.Deployments {
		if rtVersionInfo.Version != rt.Version {
			continue
		}

		if err := rt.Capabilities.TEE.Verify(teeCfg, ts, height, rtVersionInfo.TEE, nodeID); err != nil {
			logger.Error("VerifyNodeRuntimeEnclaveIDs: failed to validate attestation",
				"node_id", nodeID,
				"runtime_id", rt.ID,
				"ts", ts,
				"err", err,
			)
			return err
		}

		return nil
	}

	logger.Error("VerifyNodeRuntimeEnclaveIDs: node running unknown enclave version",
		"runtime_id", rt.ID,
		"version", rt.Version,
		"ts", ts,
	)
	return fmt.Errorf("%w: node running unknown runtime enclave version", ErrInvalidArgument)
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
func verifyNodeRuntimeChanges(
	ctx context.Context,
	logger *logging.Logger,
	currentRuntimes, newRuntimes []*node.Runtime,
	runtimeLookup RuntimeLookup,
	epoch beacon.EpochTime,
) bool {
	// Note: VerifyNodeRuntimeEnclaveIDs ensures that nothing outrageous
	// is in newRuntimes, this routine only needs to validate changes.

	toMap := func(vec []*node.Runtime) (map[common.Namespace]map[version.Version]*node.Runtime, error) {
		m := make(map[common.Namespace]map[version.Version]*node.Runtime)
		for i := range vec {
			rt := vec[i]
			if m[rt.ID] == nil {
				m[rt.ID] = make(map[version.Version]*node.Runtime)
			}
			if m[rt.ID][rt.Version] != nil {
				return nil, fmt.Errorf("registry: redundant versions for runtime: %s", rt.ID)
			}
			m[rt.ID][rt.Version] = rt
		}
		return m, nil
	}

	currentMap, err := toMap(currentRuntimes)
	if err != nil {
		// Invariant violation, corrupt state.
		logger.Error("RegisterNode: trying to update runtimes, current runtime state corrupt",
			"err", err,
			"current_runtimes", currentRuntimes,
		)
		panic(fmt.Sprintf("RegisterNode: malformed node runtimes present in state: %v", err))
	}

	newMap, err := toMap(newRuntimes)
	if err != nil {
		logger.Error("RegisterNode: trying to update runtimes, new runtime state invalid",
			"err", err,
			"new_runtimes", newRuntimes,
		)
		return false
	}

	for id, currentVersions := range currentMap {
		// All runtimes in currentMap need to be present in newMap.
		newVersions, ok := newMap[id]
		if !ok {
			logger.Error("RegisterNode: trying to update runtimes, current runtime is missing in new set",
				"runtime_id", id,
			)
			return false
		}

		rtDesc, err := runtimeLookup.AnyRuntime(ctx, id)
		if err != nil {
			logger.Error("RegisterNode: trying to update runtimes, unknown runtime",
				"runtime_id", id,
			)
			return false
		}
		activeDeployment := rtDesc.ActiveDeployment(epoch)

		// All versions present in currentMap for a runtime, that are
		// also present in newMap, need to report identical capabilities.
		for version, currentRuntime := range currentVersions {
			newRuntime, ok := newVersions[version]
			if !ok {
				if activeDeployment == nil {
					// If there is no active deployment, it is fine if the node
					// does whatever they want.
					continue
				}
				if version.ToU64() < activeDeployment.Version.ToU64() {
					// If the missing runtime is NOT the active deployment
					// and will not become active in the future, the node
					// can chose not to include it in the registration.
					continue
				}
				if vi := rtDesc.DeploymentForVersion(version); vi == nil {
					// If the missing version is no longer scheduled, it is
					// fine if the node does not include it.
					continue
				}

				logger.Error("RegisterNode: trying to update runtimes, current version is missing in new set",
					"runtime_id", id,
					"version", version,
				)
				return false
			}

			if !verifyRuntimeCapabilities(logger, &currentRuntime.Capabilities, &newRuntime.Capabilities) { //nolint:gosec
				curRtJSON, _ := json.Marshal(currentRuntime)
				newRtJSON, _ := json.Marshal(newRuntime)
				logger.Error("RegisterNode: trying to update runtimes, runtime Capabilities changed",
					"runtime_id", id,
					"version", version,
					"current_runtime", curRtJSON,
					"new_runtime", newRtJSON,
				)
				return false
			}
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
func VerifyNodeUpdate(
	ctx context.Context,
	logger *logging.Logger,
	currentNode, newNode *node.Node,
	runtimeLookup RuntimeLookup,
	epoch beacon.EpochTime,
) error {
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
	// Every node requires a Consensus.ID and it shouldn't be updated.
	if !currentNode.Consensus.ID.Equal(newNode.Consensus.ID) {
		logger.Error("RegisterNode: trying to update consensus ID",
			"current_id", currentNode.Consensus.ID,
			"new_id", newNode.Consensus.ID,
		)
		return ErrNodeUpdateNotAllowed
	}

	// Following checks are only done for active nodes.
	if currentNode.IsExpired(uint64(epoch)) {
		return nil
	}

	if !verifyNodeRuntimeChanges(ctx, logger, currentNode.Runtimes, newNode.Runtimes, runtimeLookup, epoch) {
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

	return nil
}

// VerifyRuntime verifies the given runtime.
func VerifyRuntime( // nolint: gocyclo
	params *ConsensusParameters,
	logger *logging.Logger,
	rt *Runtime,
	isGenesis bool,
	isSanityCheck bool,
	now beacon.EpochTime,
) error {
	if rt == nil {
		return fmt.Errorf("%w: no runtime given", ErrInvalidArgument)
	}

	if err := rt.ValidateBasic(!isGenesis && !isSanityCheck); err != nil {
		logger.Error("RegisterRuntime: invalid runtime descriptor",
			"runtime", rt,
			"err", err,
		)
		return fmt.Errorf("%w: %s", ErrInvalidArgument, err)
	}

	if rt.ID.IsTest() && !params.DebugAllowTestRuntimes {
		logger.Error("RegisterRuntime: test runtime registration not allowed",
			"id", rt.ID,
		)
		return fmt.Errorf("%w: test runtime not allowed", ErrInvalidArgument)
	}

	if err := rt.Genesis.SanityCheck(isGenesis); err != nil {
		return err
	}

	// Make sure the specified runtime governance model is allowed.
	if len(params.EnableRuntimeGovernanceModels) == 0 {
		// No runtime governance models are allowed.
		return fmt.Errorf("%w: no runtime governance models are enabled", ErrForbidden)
	}
	if !params.EnableRuntimeGovernanceModels[rt.GovernanceModel] {
		// Specified governance model is not allowed.
		return fmt.Errorf("%w: runtime governance model is not enabled: %s", ErrForbidden, rt.GovernanceModel.String())
	}

	// Ensure a valid TEE hardware is specified.
	if rt.TEEHardware >= node.TEEHardwareReserved {
		logger.Error("RegisterRuntime: invalid TEE hardware specified",
			"runtime", rt,
		)
		return fmt.Errorf("%w: invalid TEE hardware", ErrInvalidArgument)
	}

	// Validate the deployments.  This also handles validating that the
	// appropriate TEE configuration is present in each deployment.
	if err := rt.ValidateDeployments(now, params); err != nil {
		logger.Error("RegisterRuntime: invalid deployments",
			"runtime_id", rt.ID,
			"err", err,
		)
		return err // ValidateDeployments handles wrapping, yay.
	}

	// Using runtime governance for non-compute runtimes is invalid.
	if rt.GovernanceModel == GovernanceRuntime && rt.Kind != KindCompute {
		logger.Error("RegisterRuntime: runtime governance can only be used with compute runtimes")
		return fmt.Errorf("%w: runtime governance can only be used with compute runtimes", ErrInvalidArgument)
	}

	return nil
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

// VerifyRuntimeNew verifies a new runtime.
func VerifyRuntimeNew(logger *logging.Logger, rt *Runtime, now beacon.EpochTime, params *ConsensusParameters, isGenesis bool) error {
	if !(isGenesis || params.DebugDeployImmediately) {
		// Unless isGenesis or debug option set, forbid immediate deployment.
		if rt.ActiveDeployment(now) != nil {
			logger.Error("RegisterRuntime: trying to deploy immediately",
				"runtime_id", rt.ID,
			)
			return ErrRuntimeUpdateNotAllowed
		}
	}
	return nil
}

// VerifyRuntimeUpdate verifies changes while updating the runtime.
func VerifyRuntimeUpdate(
	logger *logging.Logger,
	currentRt, newRt *Runtime,
	now beacon.EpochTime,
	params *ConsensusParameters,
) error {
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
	// Going from having a key manager to no key manager is not allowed.
	if currentRt.KeyManager != nil && newRt.KeyManager == nil {
		logger.Error("RegisterRuntime: trying to remove key manager",
			"current_km", currentRt.KeyManager,
			"new_km", newRt.KeyManager,
		)
		return ErrRuntimeUpdateNotAllowed
	}
	// If the key manager was set before it must not change.
	if currentRt.KeyManager != nil && !currentRt.KeyManager.Equal(newRt.KeyManager) {
		logger.Error("RegisterRuntime: trying to change key manager",
			"current_km", currentRt.KeyManager,
			"new_km", newRt.KeyManager,
		)
		return ErrRuntimeUpdateNotAllowed
	}
	// Check if governance model update is valid.
	if currentRt.GovernanceModel != newRt.GovernanceModel {
		// Transitioning from entity to runtime governance is allowed, but
		// all other transitions are not.
		if !(currentRt.GovernanceModel == GovernanceEntity && newRt.GovernanceModel == GovernanceRuntime) {
			logger.Error("RegisterRuntime: invalid governance model transition",
				"current_gm", currentRt.GovernanceModel.String(),
				"new_gm", newRt.GovernanceModel.String(),
			)
			return ErrRuntimeUpdateNotAllowed
		}
	}
	// Using runtime governance for non-compute runtimes is invalid.
	if newRt.GovernanceModel == GovernanceRuntime && newRt.Kind != KindCompute {
		logger.Error("RegisterRuntime: runtime governance can only be used with compute runtimes")
		return ErrRuntimeUpdateNotAllowed
	}

	// Validate the deployments.
	activeDeployment := currentRt.ActiveDeployment(now)
	if err := currentRt.ValidateDeployments(now, params); err != nil {
		// Invariant violation, this should NEVER happen.
		logger.Error("RegisterRuntime: malformed deployments present in state",
			"runtime_id", currentRt.ID,
			"err", err,
		)
		panic(fmt.Sprintf("RegisterRuntime: malformed deployments present in state: %s: %v", currentRt.ID, err))
	}
	existingDeployments := make(map[version.Version]*VersionInfo)
	for i, deployment := range currentRt.Deployments {
		existingDeployments[deployment.Version] = currentRt.Deployments[i]
	}

	newActiveDeployment := newRt.ActiveDeployment(now)
	if err := newRt.ValidateDeployments(now, params); err != nil {
		logger.Error("RegisterRuntime: malformed deployments",
			"runtime_id", currentRt.ID,
			"err", err,
		)
		return ErrRuntimeUpdateNotAllowed
	}
	newDeployments := make(map[version.Version]*VersionInfo)
	for i, deployment := range newRt.Deployments {
		newDeployments[deployment.Version] = newRt.Deployments[i]
	}

	for newVersion, newInfo := range newDeployments {
		oldInfo := existingDeployments[newVersion]

		// If this is a version that is present in the old descriptor...
		if oldInfo != nil {
			// If nothing has changed just continue.
			if newInfo.Equal(oldInfo) {
				continue
			}

			// This is valid if it is altering an existing future deployment.
		}

		// This prevents altering existing deployments and updates that
		// attempt to deploy retroactively (new deployments must have
		// the validity window start at some point in the future).
		if newInfo.ValidFrom <= now {
			logger.Error("RegisterRuntime: trying to change an existing deployment",
				"runtime_id", currentRt.ID,
				"version", newVersion,
			)
			return ErrRuntimeUpdateNotAllowed
		}
	}

	if activeDeployment != nil {
		if newActiveDeployment == nil {
			logger.Error("RegisterRuntime: trying to remove an existing deployment",
				"runtime_id", currentRt.ID,
			)
			return ErrRuntimeUpdateNotAllowed
		}

		// Double check this just to be sure.
		if !activeDeployment.Equal(newActiveDeployment) {
			logger.Error("RegisterRuntime: trying to change the active deployment",
				"runtime_id", currentRt.ID,
			)
			return ErrRuntimeUpdateNotAllowed
		}
	} else if newActiveDeployment != nil {
		// Fail.  Immediate deployment not allowed.
		logger.Error("RegisterRuntime: trying to deploy immediately",
			"runtime_id", currentRt.ID,
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
	Runtimes []*Runtime `json:"runtimes,omitempty"`
	// SuspendedRuntimes is the list of suspended runtimes.
	SuspendedRuntimes []*Runtime `json:"suspended_runtimes,omitempty"`

	// Nodes is the initial list of nodes.
	Nodes []*node.MultiSignedNode `json:"nodes,omitempty"`

	// NodeStatuses is a set of node statuses.
	NodeStatuses map[signature.PublicKey]*NodeStatus `json:"node_statuses,omitempty"`
}

// ConsensusParameters are the registry consensus parameters.
type ConsensusParameters struct {
	// DebugAllowUnroutableAddresses is true iff node registration should
	// allow unroutable addresses.
	DebugAllowUnroutableAddresses bool `json:"debug_allow_unroutable_addresses,omitempty"`

	// DebugAllowTestRuntimes is true iff test runtimes should be allowed to
	// be registered.
	DebugAllowTestRuntimes bool `json:"debug_allow_test_runtimes,omitempty"`

	// DebugBypassStake is true iff the registry should bypass all of the staking
	// related checks and operations.
	DebugBypassStake bool `json:"debug_bypass_stake,omitempty"`

	// DebugDeployImmediately is true iff runtime registrations should
	// allow immediate deployment.
	DebugDeployImmediately bool `json:"debug_deploy_immediately,omitempty"`

	// DisableRuntimeRegistration is true iff runtime registration should be
	// disabled outside of the genesis block.
	DisableRuntimeRegistration bool `json:"disable_runtime_registration,omitempty"`

	// DisableKeyManagerRuntimeRegistration is true iff key manager runtime registration should be
	// disabled outside of the genesis block.
	DisableKeyManagerRuntimeRegistration bool `json:"disable_km_runtime_registration,omitempty"`

	// EnableKeyManagerCHURP is true iff the CHURP extension for the key manager is enabled.
	EnableKeyManagerCHURP bool `json:"enable_km_churp,omitempty"`

	// GasCosts are the registry transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// MaxNodeExpiration is the maximum number of epochs relative to the epoch
	// at registration time that a single node registration is valid for.
	MaxNodeExpiration uint64 `json:"max_node_expiration,omitempty"`

	// EnableRuntimeGovernanceModels is a set of enabled runtime governance models.
	EnableRuntimeGovernanceModels map[RuntimeGovernanceModel]bool `json:"enable_runtime_governance_models,omitempty"`

	// TEEFeatures contains the configuration of supported TEE features.
	TEEFeatures *node.TEEFeatures `json:"tee_features,omitempty"`

	// MaxRuntimeDeployments is the maximum number of runtime deployments.
	MaxRuntimeDeployments uint8 `json:"max_runtime_deployments,omitempty"`
}

// ConsensusParameterChanges are allowed registry consensus parameter changes.
type ConsensusParameterChanges struct {
	// DisableRuntimeRegistration is the new disable runtime registration flag.
	DisableRuntimeRegistration *bool `json:"disable_runtime_registration,omitempty"`

	// DisableKeyManagerRuntimeRegistration the new disable key manager runtime registration flag.
	DisableKeyManagerRuntimeRegistration *bool `json:"disable_km_runtime_registration,omitempty"`

	// GasCosts are the new gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// MaxNodeExpiration is the maximum node expiration.
	MaxNodeExpiration *uint64 `json:"max_node_expiration,omitempty"`

	// EnableRuntimeGovernanceModels are the new enabled runtime governance models.
	EnableRuntimeGovernanceModels map[RuntimeGovernanceModel]bool `json:"enable_runtime_governance_models,omitempty"`

	// TEEFeatures are the new TEE features.
	TEEFeatures **node.TEEFeatures `json:"tee_features,omitempty"`

	// MaxRuntimeDeployments is the new maximum number of runtime deployments.
	MaxRuntimeDeployments *uint8 `json:"max_runtime_deployments,omitempty"`
}

// Apply applies changes to the given consensus parameters.
func (c *ConsensusParameterChanges) Apply(params *ConsensusParameters) error {
	if c.DisableRuntimeRegistration != nil {
		params.DisableRuntimeRegistration = *c.DisableRuntimeRegistration
	}
	if c.DisableKeyManagerRuntimeRegistration != nil {
		params.DisableKeyManagerRuntimeRegistration = *c.DisableKeyManagerRuntimeRegistration
	}
	if c.GasCosts != nil {
		params.GasCosts = c.GasCosts
	}
	if c.MaxNodeExpiration != nil {
		params.MaxNodeExpiration = *c.MaxNodeExpiration
	}
	if c.EnableRuntimeGovernanceModels != nil {
		params.EnableRuntimeGovernanceModels = c.EnableRuntimeGovernanceModels
	}
	if c.TEEFeatures != nil {
		params.TEEFeatures = *c.TEEFeatures
	}
	if c.MaxRuntimeDeployments != nil {
		params.MaxRuntimeDeployments = *c.MaxRuntimeDeployments
	}
	return nil
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
	// GasOpProveFreshness is the gas operation identifier for freshness proofs.
	GasOpProveFreshness transaction.Op = "prove_freshness"
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
	GasOpProveFreshness:          1000,
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
	return staking.StakeClaim(fmt.Sprintf(StakeClaimRegisterRuntime, id.Hex()))
}

// StakeThresholdsForNode returns the staking thresholds for the given node.
//
// The passed list of runtimes must be unique runtime descriptors for all runtimes that the node is
// registered for.
func StakeThresholdsForNode(n *node.Node, rts []*Runtime) (thresholds []staking.StakeThreshold) {
	// Validator nodes are global.
	if n.HasRoles(node.RoleValidator) {
		thresholds = append(thresholds, staking.GlobalStakeThreshold(staking.KindNodeValidator))
	}

	runtimes := make(map[common.Namespace]*Runtime)
	for _, rt := range rts {
		runtimes[rt.ID] = rt
	}

	// Add runtime-specific role thresholds for each registered runtime.
	seen := make(map[common.Namespace]struct{})
	for _, nodeRt := range n.Runtimes {
		// A runtime can be included multiple times due to multiple deployments/versions.
		if _, ok := seen[nodeRt.ID]; ok {
			continue
		}
		seen[nodeRt.ID] = struct{}{}

		// Grab the runtime descriptor.
		rt, exists := runtimes[nodeRt.ID]
		if !exists {
			panic(fmt.Errorf("registry: runtime %s not provided for computing thresholds", nodeRt.ID))
		}

		var roleThresholds []staking.ThresholdKind
		if n.HasRoles(node.RoleKeyManager) {
			roleThresholds = append(roleThresholds, staking.KindNodeKeyManager)
		}
		if n.HasRoles(node.RoleComputeWorker) {
			roleThresholds = append(roleThresholds, staking.KindNodeCompute)
		}
		if n.HasRoles(node.RoleObserver) {
			roleThresholds = append(roleThresholds, staking.KindNodeObserver)
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
