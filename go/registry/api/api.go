// Package api implements the runtime and entity registry APIs.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
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

	// ErrForbidden is the error returned when an operation is forbiden by
	// policy.
	ErrForbidden = errors.New(ModuleName, 16, "registry: forbidden by policy")

	// ErrNodeUpdateNotAllowed is the error returned when trying to update an existing node with
	// disallowed changes.
	ErrNodeUpdateNotAllowed = errors.New(ModuleName, 17, "registry: node update not allowed")

	// ErrRuntimeUpdateNotAllowed is the error returned when trying to update an existing runtime.
	ErrRuntimeUpdateNotAllowed = errors.New(ModuleName, 18, "registry: runtime update not allowed")

	// MethodRegisterEntity is the method name for entity registrations.
	MethodRegisterEntity = transaction.NewMethodName(ModuleName, "RegisterEntity", entity.SignedEntity{})
	// MethodDeregisterEntity is the method name for entity deregistrations.
	MethodDeregisterEntity = transaction.NewMethodName(ModuleName, "DeregisterEntity", nil)
	// MethodRegisterNode is the method name for node registrations.
	MethodRegisterNode = transaction.NewMethodName(ModuleName, "RegisterNode", node.SignedNode{})
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

	// ConsensusAddressRequiredRoles are the Node roles that require Consensus Address.
	ConsensusAddressRequiredRoles = node.RoleValidator

	// CommitteeAddressRequiredRoles are the Node roles that require Committee Address.
	CommitteeAddressRequiredRoles = (node.RoleComputeWorker |
		node.RoleStorageWorker |
		node.RoleKeyManager)

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

	// WatchNodes returns a channel that produces a stream of
	// NodeEvent on node registration changes.
	WatchNodes(context.Context) (<-chan *NodeEvent, pubsub.ClosableSubscription, error)

	// WatchNodeList returns a channel that produces a stream of NodeList.
	// Upon subscription, the node list for the current epoch will be sent
	// immediately if available.
	//
	// Each node list will be sorted by node ID in lexographically ascending
	// order.
	WatchNodeList(context.Context) (<-chan *NodeList, pubsub.ClosableSubscription, error)

	// GetRuntime gets a runtime by ID.
	GetRuntime(context.Context, *NamespaceQuery) (*Runtime, error)

	// GetRuntimes returns the registered Runtimes at the specified
	// block height.
	GetRuntimes(context.Context, int64) ([]*Runtime, error)

	// GetNodeList returns the NodeList at the specified block height.
	GetNodeList(context.Context, int64) (*NodeList, error)

	// WatchRuntimes returns a stream of Runtime.  Upon subscription,
	// all runtimes will be sent immediately.
	WatchRuntimes(context.Context) (<-chan *Runtime, pubsub.ClosableSubscription, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(context.Context, int64) (*Genesis, error)

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

// NewRegisterEntityTx creates a new register entity transaction.
func NewRegisterEntityTx(nonce uint64, fee *transaction.Fee, sigEnt *entity.SignedEntity) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodRegisterEntity, sigEnt)
}

// NewDeregisterEntityTx creates a new deregister entity transaction.
func NewDeregisterEntityTx(nonce uint64, fee *transaction.Fee) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodDeregisterEntity, nil)
}

// NewRegisterNodeTx creates a new register node transaction.
func NewRegisterNodeTx(nonce uint64, fee *transaction.Fee, sigNode *node.SignedNode) *transaction.Transaction {
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

// NodeLookup interface implements various ways for the verification
// functions to look-up nodes in the registry's state.
type NodeLookup interface {
	// Returns the node that corresponds to the given consensus or P2P ID.
	NodeByConsensusOrP2PKey(key signature.PublicKey) (*node.Node, error)

	// Returns the node that corresponds to the given committee certificate.
	NodeByCertificate(cert []byte) (*node.Node, error)
}

// RuntimeLookup interface implements various ways for the verification
// functions to look-up runtimes in the registry's state.
type RuntimeLookup interface {
	// Runtime looks up a runtime by its identifier and returns it.
	//
	// This excludes any suspended runtimes, use SuspendedRuntime to query suspended runtimes only.
	Runtime(id common.Namespace) (*Runtime, error)

	// SuspendedRuntime looks up a suspended runtime by its identifier and
	// returns it.
	SuspendedRuntime(id common.Namespace) (*Runtime, error)

	// AnyRuntime looks up either an active or suspended runtime by its identifier and returns it.
	AnyRuntime(id common.Namespace) (*Runtime, error)
}

// VerifyRegisterEntityArgs verifies arguments for RegisterEntity.
func VerifyRegisterEntityArgs(logger *logging.Logger, sigEnt *entity.SignedEntity, isGenesis bool) (*entity.Entity, error) {
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
	if sigEnt.Signed.Signature.SanityCheck(ent.ID) != nil {
		logger.Error("RegisterEntity: invalid argument(s)",
			"signed_entity", sigEnt,
			"entity", ent,
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
			return nil, ErrInvalidArgument
		}

		if nodesMap[v] {
			logger.Error("RegisterEntity: duplicate entries in node list",
				"entity", ent,
			)
			return nil, ErrInvalidArgument
		}
		nodesMap[v] = true
	}

	return &ent, nil
}

// VerifyRegisterNodeArgs verifies arguments for RegisterNode.
//
// Returns the node descriptor and a list of runtime descriptors the node is registering for.
func VerifyRegisterNodeArgs( // nolint: gocyclo
	params *ConsensusParameters,
	logger *logging.Logger,
	sigNode *node.SignedNode,
	entity *entity.Entity,
	now time.Time,
	isGenesis bool,
	runtimeLookup RuntimeLookup,
	nodeLookup NodeLookup,
) (*node.Node, []*Runtime, error) {
	var n node.Node
	if sigNode == nil {
		return nil, nil, ErrInvalidArgument
	}

	var ctx signature.Context
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
		return nil, nil, ErrInvalidSignature
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
		return nil, nil, ErrInvalidArgument
	}

	// Validate that the node is signed by the correct signer.
	if sigNode.Signed.Signature.SanityCheck(expectedSigner) != nil {
		logger.Error("RegisterNode: not signed by expected signer",
			"signed_node", sigNode,
			"node", n,
			"entity", entity,
		)
		return nil, nil, ErrInvalidArgument
	}

	// Make sure that a node has at least one valid role.
	switch {
	case n.Roles == 0:
		logger.Error("RegisterNode: no roles specified",
			"node", n,
		)
		return nil, nil, ErrInvalidArgument
	case n.HasRoles(node.RoleReserved):
		logger.Error("RegisterNode: invalid role specified",
			"node", n,
		)
		return nil, nil, ErrInvalidArgument
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
			return nil, nil, ErrInvalidArgument
		}
	default:
		rtMap := make(map[common.Namespace]bool)

		for _, rt := range n.Runtimes {
			if rtMap[rt.ID] {
				logger.Error("RegisterNode: duplicate runtime IDs",
					"runtime_id", rt.ID,
				)
				return nil, nil, ErrInvalidArgument
			}
			rtMap[rt.ID] = true

			// Make sure that the claimed runtime actually exists.
			regRt, err := runtimeLookup.AnyRuntime(rt.ID)
			if err != nil {
				logger.Error("RegisterNode: failed to fetch supported runtime",
					"err", err,
					"runtime_id", rt.ID,
				)
				return nil, nil, ErrInvalidArgument
			}

			// If the node indicates TEE support for any of it's runtimes,
			// validate the attestation evidence.
			if err := VerifyNodeRuntimeEnclaveIDs(logger, rt, regRt, now); err != nil {
				return nil, nil, err
			}

			runtimes = append(runtimes, regRt)
		}
	}

	// Validate ConsensusInfo.
	if !n.Consensus.ID.IsValid() {
		logger.Error("RegisterNode: invalid consensus id",
			"node", n,
		)
		return nil, nil, ErrInvalidArgument
	}
	consensusAddressRequired := n.HasRoles(ConsensusAddressRequiredRoles)
	if !isGenesis {
		// XXX: Re-enable consensus address checks at genesis after
		// existing deployments have cleaned up registries.
		// https://github.com/oasislabs/oasis-core/issues/2428
		if err := verifyAddresses(params, consensusAddressRequired, n.Consensus.Addresses); err != nil {
			addrs, _ := json.Marshal(n.Consensus.Addresses)
			logger.Error("RegisterNode: missing/invalid consensus addresses",
				"node", n,
				"consensus_addrs", addrs,
			)
			return nil, nil, err
		}
	}

	// If node is a key manager, ensure that it is owned by the key manager
	// operator.
	if n.HasRoles(node.RoleKeyManager) {
		if !n.EntityID.Equal(params.KeyManagerOperator) {
			logger.Error("RegisterNode: key manager not owned by key manager operator",
				"node", n,
			)
			return nil, nil, ErrInvalidArgument
		}
	}

	// Validate CommitteeInfo.
	// Verify that certificate is well-formed.
	if _, err := n.Committee.ParseCertificate(); err != nil {
		logger.Error("RegisterNode: invalid committee TLS certificate",
			"node", n,
			"err", err,
		)
		return nil, nil, ErrInvalidArgument
	}
	committeeAddressRequired := n.HasRoles(CommitteeAddressRequiredRoles)
	if err := verifyAddresses(params, committeeAddressRequired, n.Committee.Addresses); err != nil {
		addrs, _ := json.Marshal(n.Committee.Addresses)
		logger.Error("RegisterNode: missing/invalid committee addresses",
			"node", n,
			"committee_addrs", addrs,
		)
		return nil, nil, err
	}

	// Validate P2PInfo.
	if !n.P2P.ID.IsValid() {
		logger.Error("RegisterNode: invalid P2P id",
			"node", n,
		)
		return nil, nil, ErrInvalidArgument
	}
	p2pAddressRequired := n.HasRoles(P2PAddressRequiredRoles)
	if err := verifyAddresses(params, p2pAddressRequired, n.P2P.Addresses); err != nil {
		addrs, _ := json.Marshal(n.P2P.Addresses)
		logger.Error("RegisterNode: missing/invald P2P addresses",
			"node", n,
			"p2p_addrs", addrs,
		)
		return nil, nil, err
	}

	// Make sure that the consensus and P2P keys, as well as the committee
	// certificate are unique (between themselves and compared to other nodes).
	//
	// Note that if a key exists and belongs to the same node ID, this is not
	// counted as an error, since it is possible that the node descriptor is
	// just being updated (this check is called in both cases).
	if n.Consensus.ID.Equal(n.P2P.ID) {
		logger.Error("RegisterNode: node consensus and P2P IDs must differ",
			"node", n,
		)
		return nil, nil, ErrInvalidArgument
	}

	existingNode, err := nodeLookup.NodeByConsensusOrP2PKey(n.Consensus.ID)
	if err != nil && err != ErrNoSuchNode {
		logger.Error("RegisterNode: failed to get node by consensus ID",
			"err", err,
			"consensus_id", n.Consensus.ID.String(),
		)
		return nil, nil, ErrInvalidArgument
	}
	if existingNode != nil && existingNode.ID != n.ID {
		logger.Error("RegisterNode: duplicate node consensus ID",
			"node_id", n.ID,
			"existing_node_id", existingNode.ID,
		)
		return nil, nil, ErrInvalidArgument
	}

	existingNode, err = nodeLookup.NodeByConsensusOrP2PKey(n.P2P.ID)
	if err != nil && err != ErrNoSuchNode {
		logger.Error("RegisterNode: failed to get node by p2p ID",
			"err", err,
			"p2p_id", n.P2P.ID.String(),
		)
		return nil, nil, ErrInvalidArgument
	}
	if existingNode != nil && existingNode.ID != n.ID {
		logger.Error("RegisterNode: duplicate node p2p ID",
			"node_id", n.ID,
			"existing_node_id", existingNode.ID,
		)
		return nil, nil, ErrInvalidArgument
	}

	existingNode, err = nodeLookup.NodeByCertificate(n.Committee.Certificate)
	if err != nil && err != ErrNoSuchNode {
		logger.Error("RegisterNode: failed to get node by committee certificate",
			"err", err,
		)
		return nil, nil, ErrInvalidArgument
	}
	if existingNode != nil && existingNode.ID != n.ID {
		logger.Error("RegisterNode: duplicate node committee certificate",
			"node_id", n.ID,
			"existing_node_id", existingNode.ID,
		)
		return nil, nil, ErrInvalidArgument
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
			return ErrInvalidArgument
		}

		if !addr.IsRoutable() {
			return ErrInvalidArgument
		}
	}

	return nil
}

func verifyAddresses(params *ConsensusParameters, addressRequired bool, addresses interface{}) error {
	switch addrs := addresses.(type) {
	case []node.ConsensusAddress:
		if len(addrs) == 0 && addressRequired {
			return ErrInvalidArgument
		}
		for _, v := range addrs {
			if !v.ID.IsValid() {
				return ErrInvalidArgument
			}
			if err := VerifyAddress(v.Address, params.DebugAllowUnroutableAddresses); err != nil {
				return err
			}
		}
	case []node.Address:
		if len(addrs) == 0 && addressRequired {
			return ErrInvalidArgument
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

// sortRuntimeList sorts the given runtime list to ensure a canonical order.
func sortRuntimeList(runtimes []*node.Runtime) {
	sort.Slice(runtimes, func(i, j int) bool {
		return bytes.Compare(runtimes[i].ID[:], runtimes[j].ID[:]) == -1
	})
}

// verifyNodeRuntimeChanges verifies node runtime changes.
func verifyNodeRuntimeChanges(logger *logging.Logger, currentRuntimes []*node.Runtime, newRuntimes []*node.Runtime) bool {
	sortRuntimeList(currentRuntimes)
	sortRuntimeList(newRuntimes)
	if len(currentRuntimes) != len(newRuntimes) {
		logger.Error("RegisterNode: trying to update runtimes, length mismatch",
			"current_runtimes", currentRuntimes,
			"new_runtimes", newRuntimes,
		)
		return false
	}
	for i, currentRuntime := range currentRuntimes {
		newRuntime := newRuntimes[i]
		if !currentRuntime.ID.Equal(&newRuntime.ID) {
			logger.Error("RegisterNode: trying to update runtimes, runtime ID changed",
				"current_runtime", currentRuntime,
				"new_runtime", newRuntime,
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
func verifyRuntimeCapabilities(logger *logging.Logger, currentCaps *node.Capabilities, newCaps *node.Capabilities) bool {
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

// VerifyRegisterRuntimeArgs verifies arguments for RegisterRuntime.
func VerifyRegisterRuntimeArgs(
	params *ConsensusParameters,
	logger *logging.Logger,
	sigRt *SignedRuntime,
	isGenesis bool,
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

	// TODO: Who should sign the runtime? Current compute node assumes an entity (deployer).
	switch rt.Kind {
	case KindCompute:
		if rt.KeyManager != nil && rt.ID.Equal(rt.KeyManager) {
			return nil, ErrInvalidArgument
		}

		// Ensure there is at least one member of the transaction scheduler group.
		if rt.TxnScheduler.GroupSize == 0 {
			logger.Error("RegisterRuntime: transaction scheduler group too small",
				"runtime", rt,
			)
			return nil, ErrInvalidArgument
		}

		// Ensure there is at least one member of the storage group.
		if rt.Storage.GroupSize == 0 {
			logger.Error("RegisterRuntime: storage group too small",
				"runtime", rt,
			)
			return nil, ErrInvalidArgument
		}

		if rt.ID.IsKeyManager() {
			logger.Error("RegisterRuntime: runtime ID flag mismatch",
				"kind", rt.Kind,
				"id", rt.ID,
			)
			return nil, ErrInvalidArgument
		}
	case KindKeyManager:
		if rt.KeyManager != nil {
			return nil, ErrInvalidArgument
		}
		if !rt.ID.IsKeyManager() {
			logger.Error("RegisterRuntime: runtime ID flag mismatch, expected key manager",
				"kind", rt.Kind,
				"id", rt.ID,
			)
			return nil, ErrInvalidArgument
		}
	default:
		return nil, ErrInvalidArgument
	}
	if rt.ID.IsTest() && !params.DebugAllowTestRuntimes {
		logger.Error("RegisterRuntime: test runtime registration not allowed",
			"id", rt.ID,
		)
		return nil, ErrInvalidArgument
	}

	if !isGenesis && !rt.Genesis.StateRoot.IsEmpty() {
		// TODO: Verify storage receipt for the state root, reject such registrations for now. See oasis-core#1686.
		return nil, ErrInvalidArgument
	}
	if err := rt.Genesis.SanityCheck(isGenesis); err != nil {
		return nil, err
	}

	// Ensure there is at least one member of the compute group.
	if rt.Compute.GroupSize == 0 {
		logger.Error("RegisterRuntime: compute group size too small",
			"runtime", rt,
		)
		return nil, ErrInvalidArgument
	}

	// Ensure there is at least one member of the merge group.
	if rt.Merge.GroupSize == 0 {
		logger.Error("RegisterRuntime: merge group size too small",
			"runtime", rt,
		)
		return nil, ErrInvalidArgument
	}

	// Ensure a valid TEE hardware is specified.
	if rt.TEEHardware >= node.TEEHardwareReserved {
		logger.Error("RegisterRuntime: invalid TEE hardware specified",
			"runtime", rt,
		)
		return nil, ErrInvalidArgument
	}

	return &rt, nil
}

// VerifyRegisterComputeRuntimeArgs verifies compute runtime-specific arguments for RegisterRuntime.
func VerifyRegisterComputeRuntimeArgs(logger *logging.Logger, rt *Runtime, runtimeLookup RuntimeLookup) error {
	// Check runtime's key manager, if key manager ID is set.
	if rt.KeyManager != nil {
		km, err := runtimeLookup.Runtime(*rt.KeyManager)
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
	}

	return nil
}

// VerifyRuntimeUpdate verifies changes while updating the runtime.
//
// The function assumes that the signature on the current runtime is valid and thus does not perform
// re-verification. In case the passed current runtime descriptor is corrupted, this method will
// panic as this indicates state corruption.
func VerifyRuntimeUpdate(logger *logging.Logger, currentSigRt, newSigRt *SignedRuntime, newRt *Runtime) error {
	if !currentSigRt.Signature.PublicKey.Equal(newSigRt.Signature.PublicKey) {
		logger.Error("RegisterRuntime: trying to change runtime owner",
			"current_owner", currentSigRt.Signature.PublicKey,
			"new_owner", newSigRt.Signature.PublicKey,
		)
		return ErrRuntimeUpdateNotAllowed
	}

	var currentRt Runtime
	if err := cbor.Unmarshal(currentSigRt.Blob, &currentRt); err != nil {
		logger.Error("RegisterRuntime: corrupted current runtime descriptor",
			"err", err,
		)
		panic("registry: current runtime state is corrupted")
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
	Nodes []*node.SignedNode `json:"nodes,omitempty"`

	// NodeStatuses is a set of node statuses.
	NodeStatuses map[signature.PublicKey]*NodeStatus `json:"node_statuses,omitempty"`
}

// ConsensusParameters are the registry consensus parameters.
type ConsensusParameters struct {
	// KeyManagerOperator is the ID of the entity that is allowed to operate
	// key manager nodes.
	KeyManagerOperator signature.PublicKey `json:"km_operator"`

	// DebugAllowUnroutableAddresses is true iff node registration should
	// allow unroutable addreses.
	DebugAllowUnroutableAddresses bool `json:"debug_allow_unroutable_addresses,omitempty"`

	// DebugAllowRuntimeRegistration is true iff runtime registration should be
	// allowed outside of the genesis block.
	DebugAllowRuntimeRegistration bool `json:"debug_allow_runtime_registration,omitempty"`

	// DebugAllowTestRuntimes is true iff test runtimes should be allowed to
	// be registered.
	DebugAllowTestRuntimes bool `json:"debug_allow_test_runtimes"`

	// DebugBypassStake is true iff the registry should bypass all of the staking
	// related checks and operations.
	DebugBypassStake bool `json:"debug_bypass_stake,omitempty"`

	// GasCosts are the registry transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`
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
)

// SanityCheckEntities examines the entities table.
// Returns lookup of entity ID to the entity record for use in other checks.
func SanityCheckEntities(entities []*entity.SignedEntity) (map[signature.PublicKey]*entity.Entity, error) {
	seenEntities := make(map[signature.PublicKey]*entity.Entity)
	for _, sent := range entities {
		var ent entity.Entity
		if err := sent.Open(RegisterGenesisEntitySignatureContext, &ent); err != nil {
			return nil, fmt.Errorf("unable to open signed entity")
		}

		if !ent.ID.IsValid() {
			return nil, fmt.Errorf("entity ID %s is invalid", ent.ID.String())
		}

		for _, pk := range ent.Nodes {
			if !pk.IsValid() {
				return nil, fmt.Errorf("entity ID %s has node with invalid ID %s", ent.ID.String(), pk.String())
			}
		}

		seenEntities[ent.ID] = &ent
	}

	return seenEntities, nil
}

// SanityCheckRuntimes examines the runtimes table.
// Returns lookup of runtime ID to the runtime record for use in other checks.
func SanityCheckRuntimes(runtimes []*SignedRuntime) (map[common.Namespace]*Runtime, error) {
	seenRuntimes := make(map[common.Namespace]*Runtime)
	for _, srt := range runtimes {
		var rt Runtime
		if err := srt.Open(RegisterGenesisRuntimeSignatureContext, &rt); err != nil {
			return nil, fmt.Errorf("registry: sanity check failed: unable to open signed runtime")
		}

		switch rt.Kind {
		case KindCompute:
			if rt.ID.IsKeyManager() {
				return nil, fmt.Errorf("registry: sanity check failed: compute runtime ID %s has a key manager runtime ID", rt.ID.String())
			}
		case KindKeyManager:
			if !rt.ID.IsKeyManager() {
				return nil, fmt.Errorf("registry: sanity check failed: key manager runtime ID %s does not have a key manager runtime ID", rt.ID.String())
			}
		default:
			return nil, fmt.Errorf("registry: sanity check failed: runtime ID %s is of invalid kind", rt.ID.String())
		}

		if seenRuntimes[rt.ID] != nil {
			return nil, fmt.Errorf("registry: sanity check failed: duplicate runtime ID %s", rt.ID.String())
		}

		// Check compute runtime parameters.
		if rt.Kind == KindCompute {
			// Check runtime's Compute committee parameters.
			if rt.Compute.GroupSize < 1 {
				return nil, fmt.Errorf("registry: sanity check failed: compute group size must be >= 1 node")
			}

			if rt.Compute.RoundTimeout < 1*time.Second {
				return nil, fmt.Errorf("registry: sanity check failed: compute round timeout must be >= 1 second")
			}

			if rt.Compute.RoundTimeout.Truncate(time.Second) != rt.Compute.RoundTimeout {
				return nil, fmt.Errorf("registry: sanity check failed: granularity of compute round timeout must be a second")
			}

			// Check runtime's Merge committee parameters.
			if rt.Merge.GroupSize < 1 {
				return nil, fmt.Errorf("registry: sanity check failed: merge group size must be >= 1 node")
			}

			if rt.Merge.RoundTimeout < 1*time.Second {
				return nil, fmt.Errorf("registry: sanity check failed: merge round timeout must be >= 1 second")
			}

			if rt.Merge.RoundTimeout.Truncate(time.Second) != rt.Merge.RoundTimeout {
				return nil, fmt.Errorf("registry: sanity check failed: granularity of compute round timeout must be a second")
			}

			// Check runtime's Transaction scheduler committee parameters.
			if rt.TxnScheduler.Algorithm != TxnSchedulerAlgorithmBatching {
				return nil, fmt.Errorf("registry: sanity check failed: invalid txn scheduler algorithm")
			}

			if rt.TxnScheduler.BatchFlushTimeout < 1*time.Second {
				return nil, fmt.Errorf("registry: sanity check failed: batch flush timeout must be >= 1 second")
			}

			if rt.TxnScheduler.BatchFlushTimeout.Truncate(time.Second) != rt.TxnScheduler.BatchFlushTimeout {
				return nil, fmt.Errorf("registry: sanity check failed: granularity of txn scheduler batch flush timeout must be a second")
			}

			if rt.TxnScheduler.MaxBatchSize < 1 {
				return nil, fmt.Errorf("registry: sanity check failed: max batch size must be >= 1")
			}

			if rt.TxnScheduler.MaxBatchSizeBytes < 1 {
				return nil, fmt.Errorf("registry: sanity check failed: max batch size in bytes must be >= 1")
			}

			// Check that the given key manager runtime is a valid key manager runtime.
			if rt.KeyManager != nil {
				krt := seenRuntimes[*rt.KeyManager]
				if krt == nil {
					// Not seen yet, traverse the entire runtime list (the KM runtimes
					// aren't guaranteed to be sorted before the other runtimes).
					var found bool
					for _, skrt := range runtimes {
						var kmrt Runtime
						if err := skrt.Open(RegisterGenesisRuntimeSignatureContext, &kmrt); err != nil {
							return nil, fmt.Errorf("registry: sanity check failed: unable to open signed runtime")
						}
						if kmrt.ID.Equal(rt.KeyManager) {
							found = true
							krt = &kmrt
							break
						}
					}

					if !found {
						return nil, fmt.Errorf("registry: sanity check failed: compute runtime ID %s has an unknown key manager runtime ID", rt.ID.String())
					}
				}

				if krt.Kind != KindKeyManager {
					return nil, fmt.Errorf("registry: sanity check failed: compute runtime ID %s specifies a key manager runtime that isn't a key manager runtime", rt.ID.String())
				}
			}
		}

		seenRuntimes[rt.ID] = &rt
	}

	return seenRuntimes, nil
}

// SanityCheckNodes examines the nodes table.
// Pass lookups of entities and runtimes from SanityCheckEntities
// and SanityCheckRuntimes for cross referencing purposes.
func SanityCheckNodes(nodes []*node.SignedNode, seenEntities map[signature.PublicKey]*entity.Entity, seenRuntimes map[common.Namespace]*Runtime) error { // nolint: gocyclo
	for _, sn := range nodes {
		var n node.Node
		if err := sn.Open(RegisterGenesisNodeSignatureContext, &n); err != nil {
			return fmt.Errorf("registry: sanity check failed: unable to open signed node")
		}

		if !n.ID.IsValid() {
			return fmt.Errorf("registry: sanity check failed: node ID %s is invalid", n.ID.String())
		}

		if !n.EntityID.IsValid() {
			return fmt.Errorf("registry: sanity check failed: node ID %s has invalid entity ID", n.ID.String())
		}

		if seenEntities[n.EntityID] == nil {
			return fmt.Errorf("registry: sanity check failed: node ID %s has unknown controlling entity", n.ID.String())
		}

		if n.HasRoles(node.RoleReserved) {
			return fmt.Errorf("registry: sanity check failed: node ID %s has reserved roles mask bits set", n.ID.String())
		}

		if n.HasRoles(node.RoleComputeWorker) && len(n.Runtimes) == 0 {
			return fmt.Errorf("registry: sanity check failed: compute worker node must have runtime(s)")
		}

		if n.HasRoles(node.RoleStorageWorker) && len(n.Runtimes) == 0 {
			return fmt.Errorf("registry: sanity check failed: storage worker node must have runtime(s)")
		}

		if n.HasRoles(node.RoleKeyManager) && len(n.Runtimes) == 0 {
			return fmt.Errorf("registry: sanity check failed: key manager node must have runtime(s)")
		}

		if n.HasRoles(node.RoleValidator) && !n.HasRoles(node.RoleComputeWorker) && !n.HasRoles(node.RoleStorageWorker) && !n.HasRoles(node.RoleKeyManager) && len(n.Runtimes) > 0 {
			return fmt.Errorf("registry: sanity check failed: validator node shouldn't have any runtimes")
		}

		if _, err := n.Committee.ParseCertificate(); err != nil {
			return fmt.Errorf("registry: sanity check failed: node ID %s has an invalid committee certificate", n.ID.String())
		}

		if !n.Consensus.ID.IsValid() {
			return fmt.Errorf("registry: sanity check failed: node ID %s has an invalid consensus ID", n.ID.String())
		}
		// XXX: Validate P2P.ID and Consensus/Committee/P2P addresses after
		// existing deployments have cleared up registry.
		// https://github.com/oasislabs/oasis-core/issues/2428

		for _, rt := range n.Runtimes {
			seenRT := seenRuntimes[rt.ID]
			if seenRT == nil {
				return fmt.Errorf("registry: sanity check failed: node ID %s has an unknown runtime ID", n.ID.String())
			}

			if (n.HasRoles(node.RoleKeyManager) && !n.HasRoles(node.RoleComputeWorker)) && seenRT.Kind != KindKeyManager {
				return fmt.Errorf("registry: sanity check failed: key manager node ID %s has specified a non-KM runtime %s", n.ID.String(), rt.ID.String())
			}

			if (n.HasRoles(node.RoleComputeWorker) && !n.HasRoles(node.RoleKeyManager)) && seenRT.Kind != KindCompute {
				return fmt.Errorf("registry: sanity check failed: compute node ID %s has specified a non-compute runtime %s", n.ID.String(), rt.ID.String())
			}
		}

		// If the entity doesn't allow entity-signed nodes, make sure that
		// this node also appears in the entity's node list.
		if !seenEntities[n.EntityID].AllowEntitySignedNodes {
			var found bool
			for _, enPK := range seenEntities[n.EntityID].Nodes {
				if enPK.Equal(n.ID) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("registry: sanity check failed: node ID %s was not found among nodes listed by its controlling entity", n.ID.String())
			}
		}
	}

	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	unsafeFlags := g.Parameters.DebugAllowUnroutableAddresses || g.Parameters.DebugAllowRuntimeRegistration || g.Parameters.DebugBypassStake
	if unsafeFlags && !flags.DebugDontBlameOasis() {
		return fmt.Errorf("registry: sanity check failed: one or more unsafe debug flags set")
	}

	// This could check KeyManagerOperator, but some configurations don't
	// use a key manager, so the parameter is optional.

	// Check entities.
	seenEntities, err := SanityCheckEntities(g.Entities)
	if err != nil {
		return err
	}

	// Check runtimes.
	runtimes := append([]*SignedRuntime{}, g.Runtimes...)
	runtimes = append(runtimes, g.SuspendedRuntimes...)
	seenRuntimes, err := SanityCheckRuntimes(runtimes)
	if err != nil {
		return err
	}

	// Check nodes.
	return SanityCheckNodes(g.Nodes, seenEntities, seenRuntimes)
}
