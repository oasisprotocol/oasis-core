// Package api implements the runtime and entity registry APIs.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
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
	RegisterEntitySignatureContext = signature.NewContext("EkEntReg")

	// RegisterGenesisEntitySignatureContext is the context used for
	// entity registration in the genesis document.
	RegisterGenesisEntitySignatureContext = signature.NewContext("EkEntGen")

	// DeregisterEntitySignatureContext is the context used for entity
	// deregistration.
	DeregisterEntitySignatureContext = signature.NewContext("EkEDeReg")

	// RegisterNodeSignatureContext is the context used for node
	// registration.
	RegisterNodeSignatureContext = signature.NewContext("EkNodReg")

	// RegisterGenesisNodeSignatureContext is the context used for
	// node registration in the genesis document.
	//
	// Note: This is identical to non-gensis registrations to support
	// migrating existing registrations into a new genesis document.
	RegisterGenesisNodeSignatureContext = RegisterNodeSignatureContext

	// RegisterRuntimeSignatureContext is the context used for runtime
	// registration.
	RegisterRuntimeSignatureContext = signature.NewContext("EkRunReg")

	// RegisterGenesisRuntimeSignatureContext is the context used for
	// runtime registation in the genesis document.
	RegisterGenesisRuntimeSignatureContext = signature.NewContext("EkRunGen")

	// RegisterUnfreezeNodeSignatureContext is the context used for
	// unfreezing nodes.
	RegisterUnfreezeNodeSignatureContext = signature.NewContext("EkUzNReg")

	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New("registry: invalid argument")

	// ErrInvalidSignature is the error returned on an invalid signature.
	ErrInvalidSignature = errors.New("registry: invalid signature")

	// ErrBadEntityForNode is the error returned when a node registration
	// with an unknown entity is attempted.
	ErrBadEntityForNode = errors.New("registry: unknown entity in node registration")

	// ErrBadEntityForRuntime is the error returned when a runtime
	// attempts to register with an unknown entity.
	ErrBadEntityForRuntime = errors.New("registry: unknown entity in runtime registration")

	// ErrNoEnclaveForRuntime is the error returned when a TEE runtime
	// registers with no enclave IDs.
	ErrNoEnclaveForRuntime = errors.New("registry: no enclaves for TEE runtime registration")

	// ErrBadEnclaveIdentity is the error returned when a node tries to
	// register runtimes with wrong Enclave IDs.
	ErrBadEnclaveIdentity = errors.New("registry: bad enclave id")

	// ErrBadCapabilitiesTEEHardware is the error returned when a node tries to
	// register a runtime with bad Capabilities.TEE.Hardware.
	ErrBadCapabilitiesTEEHardware = errors.New("registry: bad capabilities.TEE.Hardware")

	// ErrTEEHardwareMismatch is the error returned when a node tries to
	// register a runtime and Capabilities.TEE.Hardware mismatches the one in
	// the registry.
	ErrTEEHardwareMismatch = errors.New("registry: runtime TEE.Hardware mismatches the one in registry")

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

	// ErrNodeCannotBeUnfrozen is the error returned when a node cannot yet be
	// unfrozen due to the freeze period not being over yet.
	ErrNodeCannotBeUnfrozen = errors.New("registry: node cannot be unfrozen yet")

	// ErrEntityHasNodes is the error returned when an entity cannot be deregistered
	// as it still has nodes.
	ErrEntityHasNodes = errors.New("registry: entity still has nodes")

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
	GetEntity(context.Context, signature.PublicKey, int64) (*entity.Entity, error)

	// GetEntities gets a list of all registered entities.
	GetEntities(context.Context, int64) ([]*entity.Entity, error)

	// WatchEntities returns a channel that produces a stream of
	// EntityEvent on entity registration changes.
	WatchEntities() (<-chan *EntityEvent, *pubsub.Subscription)

	// RegisterNode registers and or updates a node with the registry.
	//
	// The signature should be made using RegisterNodeSignatureContext.
	RegisterNode(context.Context, *node.SignedNode) error

	// UnfreezeNode unfreezes a previously frozen node.
	//
	// The signature should be made using RegisterUnfreezeNodeSignatureContext
	// and must be made by the owning entity key.
	UnfreezeNode(context.Context, *SignedUnfreezeNode) error

	// GetNode gets a node by ID.
	GetNode(context.Context, signature.PublicKey, int64) (*node.Node, error)

	// GetNodeStatus returns a node's status.
	GetNodeStatus(context.Context, signature.PublicKey, int64) (*NodeStatus, error)

	// GetNodes gets a list of all registered nodes.
	GetNodes(context.Context, int64) ([]*node.Node, error)

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
	GetRuntime(context.Context, signature.PublicKey, int64) (*Runtime, error)

	// GetRuntimes returns the registered Runtimes at the specified
	// block height.
	GetRuntimes(context.Context, int64) ([]*Runtime, error)

	// GetNodeList returns the NodeList at the specified block height.
	GetNodeList(context.Context, int64) (*NodeList, error)

	// WatchRuntimes returns a stream of Runtime.  Upon subscription,
	// all runtimes will be sent immediately.
	WatchRuntimes() (<-chan *Runtime, *pubsub.Subscription)

	// ToGenesis returns the genesis state at specified block height.
	ToGenesis(context.Context, int64) (*Genesis, error)

	// Cleanup cleans up the registry backend.
	Cleanup()
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

// Timestamp is a UNIX timestamp.
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
func VerifyRegisterNodeArgs(cfg *Config, logger *logging.Logger, sigNode *node.SignedNode, entity *entity.Entity, now time.Time, isGenesis bool, kmOperator signature.PublicKey, regRuntimes []*Runtime) (*node.Node, error) {
	var n node.Node
	if sigNode == nil {
		return nil, ErrInvalidArgument
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

	// Make sure that a node has at least one valid role.
	switch {
	case n.Roles == 0:
		logger.Error("RegisterNode: no roles specified",
			"node", n,
		)
		return nil, ErrInvalidArgument
	case n.HasRoles(node.RoleReserved):
		logger.Error("RegisterNode: invalid role specified",
			"node", n,
		)
		return nil, ErrInvalidArgument
	}

	// TODO: Key manager nodes maybe should be restricted to only being a
	// key manager at the expense of breaking some of our test configs.
	needRuntimes := n.HasRoles(node.RoleComputeWorker | node.RoleKeyManager) // XXX: RoleTransactionScheduler?

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

			if err := VerifyNodeRuntimeEnclaveIDs(logger, rt, regRuntimes, now); err != nil {
				return nil, err
			}
		}
	}

	// If node is a validator, ensure it has ConensusInfo.
	if n.HasRoles(node.RoleValidator) {
		if err := verifyAddresses(cfg, n.Consensus.Addresses); err != nil {
			addrs, _ := json.Marshal(n.Consensus.Addresses)
			logger.Error("RegisterNode: missing/invalid consensus addresses",
				"node", n,
				"consensus_addrs", addrs,
			)
			return nil, err
		}
	}

	// If node is a key manager, ensure that it is owned by the key manager
	// operator.
	if n.HasRoles(node.RoleKeyManager) {
		if !n.EntityID.Equal(kmOperator) {
			logger.Error("RegisterNode: key manager not owned by key manager operator",
				"node", n,
			)
			return nil, ErrInvalidArgument
		}
	}

	// If node is a worker, ensure it has CommitteeInfo.
	if n.HasRoles(node.RoleComputeWorker | node.RoleStorageWorker | node.RoleTransactionScheduler | node.RoleKeyManager | node.RoleMergeWorker) {
		if err := verifyAddresses(cfg, n.Committee.Addresses); err != nil {
			addrs, _ := json.Marshal(n.Committee.Addresses)
			logger.Error("RegisterNode: missing/invalid committee addresses",
				"node", n,
				"committee_addrs", addrs,
			)
			return nil, err
		}

		// Verify that certificate is well-formed.
		if _, err := n.Committee.ParseCertificate(); err != nil {
			logger.Error("RegisterNode: invalid committee TLS certificate",
				"node", n,
				"err", err,
			)
			return nil, ErrInvalidArgument
		}
	}

	// If node is a compute/txnscheduler/merge worker, ensure it has P2PInfo.
	if n.HasRoles(node.RoleComputeWorker | node.RoleTransactionScheduler | node.RoleMergeWorker) {
		if err := verifyAddresses(cfg, n.P2P.Addresses); err != nil {
			addrs, _ := json.Marshal(n.P2P.Addresses)
			logger.Error("RegisterNode: missing/invald P2P addresses",
				"node", n,
				"p2p_addrs", addrs,
			)
			return nil, err
		}
	}

	return &n, nil
}

// VerifyNodeRuntimeEnclaveIDs verifies TEE-specific attributes of the node's runtime.
func VerifyNodeRuntimeEnclaveIDs(logger *logging.Logger, rt *node.Runtime, regRuntimes []*Runtime, ts time.Time) error {
	// If no TEE available, do nothing.
	if rt.Capabilities.TEE == nil {
		return nil
	}

	switch rt.Capabilities.TEE.Hardware {
	case node.TEEHardwareInvalid:
	case node.TEEHardwareIntelSGX:
		// Check MRENCLAVE/MRSIGNER.
		var eidValid bool
		var avrBundle ias.AVRBundle
		if err := avrBundle.UnmarshalCBOR(rt.Capabilities.TEE.Attestation); err != nil {
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

	regRtLoop:
		for _, regRt := range regRuntimes {
			// Make sure we compare EnclaveIdentity of the same registered RuntimeIDs only!
			if !regRt.ID.Equal(rt.ID) {
				continue
			}

			if regRt.TEEHardware != rt.Capabilities.TEE.Hardware {
				rtJSON, _ := json.Marshal(rt)
				regRtJSON, _ := json.Marshal(regRt)
				quoteJSON, _ := json.Marshal(q)
				logger.Error("VerifyNodeRuntimeEnclaveIDs: runtime TEE.Hardware mismatch",
					"quote", quoteJSON,
					"node.Runtime", rtJSON,
					"registered runtime", regRtJSON,
					"ts", ts,
				)
				return ErrTEEHardwareMismatch
			}

			var vi VersionInfoIntelSGX
			if err := cbor.Unmarshal(regRt.Version.TEE, &vi); err != nil {
				return err
			}
			for _, eid := range vi.Enclaves {
				eidMrenclave := eid.MrEnclave
				eidMrsigner := eid.MrSigner
				// Compare MRENCLAVE/MRSIGNER to the one stored in the registry.
				if bytes.Equal(eidMrenclave[:], q.Report.MRENCLAVE[:]) && bytes.Equal(eidMrsigner[:], q.Report.MRSIGNER[:]) {
					eidValid = true
					break regRtLoop
				}
			}
		}

		if !eidValid {
			if logger != nil {
				rtJSON, _ := json.Marshal(rt)
				regRuntimesJSON, _ := json.Marshal(regRuntimes)
				quoteJSON, _ := json.Marshal(q)
				logger.Error("VerifyNodeRuntimeEnclaveIDs: bad enclave ID",
					"quote", quoteJSON,
					"node.Runtime", rtJSON,
					"registered runtimes", regRuntimesJSON,
					"ts", ts,
				)
			}

			return ErrBadEnclaveIdentity
		}
	default:
		return ErrBadCapabilitiesTEEHardware
	}

	if err := rt.Capabilities.TEE.Verify(ts); err != nil {
		logger.Error("VerifyNodeRuntimeEnclaveIDs: failed to validate attestation",
			"runtime", rt.ID,
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

func verifyAddresses(cfg *Config, addrs []node.Address) error {
	// Treat having no addresses as invalid, regardless.
	if len(addrs) == 0 {
		return ErrInvalidArgument
	}

	for _, v := range addrs {
		if err := VerifyAddress(v, cfg.DebugAllowUnroutableAddresses); err != nil {
			return err
		}
	}

	return nil
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
		logger.Error("RegisterNode: trying to update runtimes, length mismatch",
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
	if currentNode.RegistrationTime > newNode.RegistrationTime {
		logger.Error("RegisterNode: current node registration time greater than new",
			"current_registration_time", currentNode.RegistrationTime,
			"new_registration_time", newNode.RegistrationTime,
		)
		return ErrNodeUpdateNotAllowed
	}

	// As of right now, every node has a consensus ID.
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
func VerifyRegisterRuntimeArgs(logger *logging.Logger, sigRt *SignedRuntime, isGenesis bool) (*Runtime, error) {
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
		if rt.ID.Equal(rt.KeyManager) {
			return nil, ErrInvalidArgument
		}

		// Ensure there is at least one member of the transaction scheduler group.
		if rt.TransactionSchedulerGroupSize == 0 {
			logger.Error("RegisterRuntime: transaction scheduler group too small",
				"runtime", rt,
			)
			return nil, ErrInvalidArgument
		}

		// Ensure there is at least one member of the storage group.
		if rt.StorageGroupSize == 0 {
			logger.Error("RegisterRuntime: storage group too small",
				"runtime", rt,
			)
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

	// Ensure there is at least one member of the replication group.
	if rt.ReplicaGroupSize == 0 {
		logger.Error("RegisterRuntime: replication group too small",
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
	Entities []*entity.SignedEntity `json:"entities,omitempty"`

	// Runtimes is the initial list of runtimes.
	Runtimes []*SignedRuntime `json:"runtimes,omitempty"`

	// Nodes is the initial list of nodes.
	Nodes []*node.SignedNode `json:"nodes,omitempty"`

	// KeyManagerOperator is the ID of the entity that is allowed to operate
	// key manager nodes.
	KeyManagerOperator signature.PublicKey `json:"km_operator"`

	// NodeStatuses is a set of node statuses.
	NodeStatuses map[signature.MapKey]*NodeStatus `json:"node_statuses,omitempty"`
}

// Config is the per-backend common configuration.
type Config struct {
	// DebugAllowUnroutableAddresses is true iff node registration should
	// allow unroutable addreses.
	DebugAllowUnroutableAddresses bool

	// DebugAllowRuntimeRegistration is true iff runtime registration should be
	// allowed outside of the genesis block.
	DebugAllowRuntimeRegistration bool

	// DebugBypassStake is true iff the registry should bypass all of the staking
	// related checks and operations.
	DebugBypassStake bool
}
