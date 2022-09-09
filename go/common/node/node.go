// Package node implements common node identity routines.
package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

var (
	// ErrInvalidRole is the error returned when a node role is invalid.
	ErrInvalidRole = errors.New("node: invalid role")
	// ErrDuplicateRole is the error returned when a node role is duplicated.
	ErrDuplicateRole = errors.New("node: duplicate role")

	// ErrInvalidTEEHardware is the error returned when a TEE hardware
	// implementation is invalid.
	ErrInvalidTEEHardware = errors.New("node: invalid TEE implementation")

	// ErrRAKHashMismatch is the error returned when the TEE attestation
	// does not contain the node's RAK hash.
	ErrRAKHashMismatch = errors.New("node: RAK hash mismatch")

	// ErrBadEnclaveIdentity is the error returned when the TEE enclave
	// identity doesn't match the required values.
	ErrBadEnclaveIdentity = errors.New("node: bad TEE enclave identity")

	// ErrInvalidAttestationSignature is the error returned when the TEE attestation
	// signature fails verification.
	ErrInvalidAttestationSignature = errors.New("node: invalid TEE attestation signature")

	// ErrAttestationNotFresh is the error returned when the TEE attestation is
	// not fresh enough.
	ErrAttestationNotFresh = errors.New("node: TEE attestation not fresh enough")
	// ErrAttestationFromFuture is the error returned when the TEE attestation appears
	// to be from the future.
	ErrAttestationFromFuture = errors.New("node: TEE attestation from the future")

	teeHashContext = []byte("oasis-core/node: TEE RAK binding")

	// AttestationSignatureContext is the signature context used for TEE attestation signatures.
	AttestationSignatureContext = signature.NewContext("oasis-core/node: TEE attestation signature")

	_ prettyprint.PrettyPrinter = (*MultiSignedNode)(nil)
)

const (
	// LatestNodeDescriptorVersion is the latest node descriptor version that should be used for all
	// new descriptors. Using earlier versions may be rejected.
	LatestNodeDescriptorVersion = 2

	// Minimum and maximum descriptor versions that are allowed.
	minNodeDescriptorVersion = 1
	maxNodeDescriptorVersion = LatestNodeDescriptorVersion
)

// Node represents public connectivity information about an Oasis node.
type Node struct { // nolint: maligned
	cbor.Versioned

	// ID is the public key identifying the node.
	ID signature.PublicKey `json:"id"`

	// EntityID is the public key identifying the Entity controlling
	// the node.
	EntityID signature.PublicKey `json:"entity_id"`

	// Expiration is the epoch in which this node's commitment expires.
	Expiration uint64 `json:"expiration"`

	// TLS contains information for connecting to this node via TLS.
	TLS TLSInfo `json:"tls"`

	// P2P contains information for connecting to this node via P2P.
	P2P P2PInfo `json:"p2p"`

	// Consensus contains information for connecting to this node as a
	// consensus member.
	Consensus ConsensusInfo `json:"consensus"`

	// VRF contains information for this node's participation in VRF
	// based elections.
	VRF *VRFInfo `json:"vrf,omitempty"`

	// DeprecatedBeacon contains information for this node's
	// participation in the old PVSS based random beacon protocol.
	DeprecatedBeacon cbor.RawMessage `json:"beacon,omitempty"`

	// Runtimes are the node's runtimes.
	Runtimes []*Runtime `json:"runtimes"`

	// Roles is a bitmask representing the node roles.
	Roles RolesMask `json:"roles"`

	// SoftwareVersion is the node's oasis-node software version.
	SoftwareVersion string `json:"software_version,omitempty"`
}

// RolesMask is Oasis node roles bitmask.
type RolesMask uint32

const (
	// RoleComputeWorker is the compute worker role.
	RoleComputeWorker RolesMask = 1 << 0
	// roleReserved2 is the reserved role (storage role in v1 descriptors).
	roleReserved2 RolesMask = 1 << 1
	// RoleKeyManager is the the key manager role.
	RoleKeyManager RolesMask = 1 << 2
	// RoleValidator is the validator role.
	RoleValidator RolesMask = 1 << 3
	// RoleConsensusRPC is the public consensus RPC services worker role.
	RoleConsensusRPC RolesMask = 1 << 4
	// RoleStorageRPC is the public storage RPC services worker role.
	RoleStorageRPC RolesMask = 1 << 5

	// RoleReserved are all the bits of the Oasis node roles bitmask
	// that are reserved and must not be used.
	RoleReserved RolesMask = ((1<<32)-1) & ^((RoleStorageRPC<<1)-1) | roleReserved2

	// Human friendly role names:

	RoleComputeWorkerName = "compute"
	RoleKeyManagerName    = "key-manager"
	RoleValidatorName     = "validator"
	RoleConsensusRPCName  = "consensus-rpc"
	RoleStorageRPCName    = "storage-rpc"

	rolesMaskStringSep = ","
)

// Roles returns a list of available valid roles.
func Roles() (roles []RolesMask) {
	return []RolesMask{
		RoleComputeWorker,
		RoleKeyManager,
		RoleValidator,
		RoleConsensusRPC,
		RoleStorageRPC,
	}
}

// IsSingleRole returns true if RolesMask encodes a single valid role.
func (m RolesMask) IsSingleRole() bool {
	// Ensures exactly one bit is set, and the set bit is a valid role.
	return m != 0 && m&(m-1) == 0 && m&RoleReserved == 0
}

func (m RolesMask) String() string {
	if m&RoleReserved != 0 {
		return "[invalid roles]"
	}

	var ret []string
	if m&RoleComputeWorker != 0 {
		ret = append(ret, RoleComputeWorkerName)
	}
	if m&RoleKeyManager != 0 {
		ret = append(ret, RoleKeyManagerName)
	}
	if m&RoleValidator != 0 {
		ret = append(ret, RoleValidatorName)
	}
	if m&RoleConsensusRPC != 0 {
		ret = append(ret, RoleConsensusRPCName)
	}
	if m&RoleStorageRPC != 0 {
		ret = append(ret, RoleStorageRPCName)
	}

	return strings.Join(ret, rolesMaskStringSep)
}

// MarshalText encodes a RolesMask into text form.
func (m RolesMask) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func checkDuplicateRole(newRole RolesMask, curRoles RolesMask) error {
	if curRoles&newRole != 0 {
		return fmt.Errorf("%w: '%s'", ErrDuplicateRole, newRole)
	}
	return nil
}

// UnmarshalText decodes a text slice into a RolesMask.
func (m *RolesMask) UnmarshalText(text []byte) error {
	*m = 0
	roles := strings.Split(string(text), rolesMaskStringSep)
	for _, role := range roles {
		switch role {
		case RoleComputeWorkerName:
			if err := checkDuplicateRole(RoleComputeWorker, *m); err != nil {
				return err
			}
			*m |= RoleComputeWorker
		case RoleKeyManagerName:
			if err := checkDuplicateRole(RoleKeyManager, *m); err != nil {
				return err
			}
			*m |= RoleKeyManager
		case RoleValidatorName:
			if err := checkDuplicateRole(RoleValidator, *m); err != nil {
				return err
			}
			*m |= RoleValidator
		case RoleConsensusRPCName:
			if err := checkDuplicateRole(RoleConsensusRPC, *m); err != nil {
				return err
			}
			*m |= RoleConsensusRPC
		case RoleStorageRPCName:
			if err := checkDuplicateRole(RoleStorageRPC, *m); err != nil {
				return err
			}
			*m |= RoleStorageRPC
		default:
			return fmt.Errorf("%w: '%s'", ErrInvalidRole, role)
		}
	}
	return nil
}

// UnmarshalCBOR is a custom deserializer that handles both v1 and v2 Node structures.
func (n *Node) UnmarshalCBOR(data []byte) error {
	// Determine Entity structure version.
	v, err := cbor.GetVersion(data)
	if err != nil {
		return err
	}
	switch v {
	case 1:
		// Old version had an extra supported role (the storage role).
		type nv2 Node
		if err := cbor.Unmarshal(data, (*nv2)(n)); err != nil {
			return err
		}

		// Convert into new format.
		n.Versioned = cbor.NewVersioned(2)
		n.Roles = n.Roles & ^roleReserved2 // Clear old storage role.
		return nil
	case 2:
		// New version, call the default unmarshaler.
		type nv2 Node
		return cbor.Unmarshal(data, (*nv2)(n))
	default:
		return fmt.Errorf("invalid node descriptor version: %d", v)
	}
}

// ValidateBasic performs basic descriptor validity checks.
func (n *Node) ValidateBasic(strictVersion bool) error {
	v := n.Versioned.V
	switch strictVersion {
	case true:
		// Only the latest version is allowed.
		if v != LatestNodeDescriptorVersion {
			return fmt.Errorf("invalid node descriptor version (expected: %d got: %d)",
				LatestNodeDescriptorVersion,
				v,
			)
		}
	case false:
		// A range of versions is allowed.
		if v < minNodeDescriptorVersion || v > maxNodeDescriptorVersion {
			return fmt.Errorf("invalid node descriptor version (min: %d max: %d)",
				minNodeDescriptorVersion,
				maxNodeDescriptorVersion,
			)
		}
	}

	// Make sure that a node has at least one valid role.
	switch {
	case n.Roles == 0:
		return fmt.Errorf("no roles specified")
	case n.HasRoles(RoleReserved):
		return fmt.Errorf("invalid role specified")
	}

	return nil
}

// AddRoles adds a new node role to the existing roles mask.
func (n *Node) AddRoles(r RolesMask) {
	n.Roles |= r
}

// HasRoles checks if the node has the specified roles.
func (n *Node) HasRoles(r RolesMask) bool {
	return n.Roles&r != 0
}

// OnlyHasRoles checks if the node only has the specified roles and no others.
func (n *Node) OnlyHasRoles(r RolesMask) bool {
	return n.Roles == r
}

// IsExpired returns true if the node expiration epoch is strictly smaller
// than the passed (current) epoch.
func (n *Node) IsExpired(epoch uint64) bool {
	return n.Expiration < epoch
}

// HasRuntime returns true iff the node supports a runtime (ignoring version).
func (n *Node) HasRuntime(id common.Namespace) bool {
	for _, rt := range n.Runtimes {
		if rt.ID.Equal(&id) {
			return true
		}
	}
	return false
}

// GetRuntime searches for an existing supported runtime descriptor
// in Runtimes with the specified version and returns it.
func (n *Node) GetRuntime(id common.Namespace, version version.Version) *Runtime {
	for _, rt := range n.Runtimes {
		if !rt.ID.Equal(&id) {
			continue
		}
		if rt.Version != version {
			continue
		}
		return rt
	}
	return nil
}

// AddOrUpdateRuntime searches for an existing supported runtime descriptor
// in Runtimes with the specified version and returns it. In case a
// runtime descriptor for the given runtime and version doesn't exist yet,
// a new one is created appended to the list of supported runtimes and
// returned.
func (n *Node) AddOrUpdateRuntime(id common.Namespace, version version.Version) *Runtime {
	if rt := n.GetRuntime(id, version); rt != nil {
		return rt
	}

	rt := &Runtime{
		ID:      id,
		Version: version,
	}
	n.Runtimes = append(n.Runtimes, rt)
	return rt
}

// Runtime represents the runtimes supported by a given Oasis node.
type Runtime struct {
	// ID is the public key identifying the runtime.
	ID common.Namespace `json:"id"`

	// Version is the version of the runtime.
	Version version.Version `json:"version"`

	// Capabilities are the node's capabilities for a given runtime.
	Capabilities Capabilities `json:"capabilities"`

	// ExtraInfo is the extra per node + per runtime opaque data associated
	// with the current instance.
	ExtraInfo []byte `json:"extra_info"`
}

// TLSInfo contains information for connecting to this node via TLS.
type TLSInfo struct {
	// PubKey is the public key used for establishing TLS connections.
	PubKey signature.PublicKey `json:"pub_key"`

	// NextPubKey is the public key that will be used for establishing TLS connections after
	// certificate rotation (if enabled).
	NextPubKey signature.PublicKey `json:"next_pub_key,omitempty"`

	// Addresses is the list of addresses at which the node can be reached.
	Addresses []TLSAddress `json:"addresses"`
}

// Equal compares vs another TLSInfo for equality.
func (t *TLSInfo) Equal(other *TLSInfo) bool {
	if !t.PubKey.Equal(other.PubKey) {
		return false
	}

	if !t.NextPubKey.Equal(other.NextPubKey) {
		return false
	}

	if len(t.Addresses) != len(other.Addresses) {
		return false
	}
	for i, ca := range t.Addresses {
		if !ca.Equal(&other.Addresses[i]) {
			return false
		}
	}

	return true
}

// P2PInfo contains information for connecting to this node via P2P transport.
type P2PInfo struct {
	// ID is the unique identifier of the node on the P2P transport.
	ID signature.PublicKey `json:"id"`

	// Addresses is the list of addresses at which the node can be reached.
	Addresses []Address `json:"addresses"`
}

// ConsensusInfo contains information for connecting to this node as a
// consensus member.
type ConsensusInfo struct {
	// ID is the unique identifier of the node as a consensus member.
	ID signature.PublicKey `json:"id"`

	// Addresses is the list of addresses at which the node can be reached.
	Addresses []ConsensusAddress `json:"addresses"`
}

// VRFInfo contains information for this node's participation in
// VRF based elections.
type VRFInfo struct {
	// ID is the unique identifier of the node used to generate VRF proofs.
	ID signature.PublicKey `json:"id"`
}

// Capabilities represents a node's capabilities.
type Capabilities struct {
	// TEE is the capability of a node executing batches in a TEE.
	TEE *CapabilityTEE `json:"tee,omitempty"`
}

// TEEHardware is a TEE hardware implementation.
type TEEHardware uint8

// TEE Hardware implementations.
const (
	// TEEHardwareInvalid is a non-TEE implementation.
	TEEHardwareInvalid TEEHardware = 0
	// TEEHardwareIntelSGX is an Intel SGX TEE implementation.
	TEEHardwareIntelSGX TEEHardware = 1

	// TEEHardwareReserved is the first reserved hardware implementation
	// identifier. All equal or greater identifiers are reserved.
	TEEHardwareReserved TEEHardware = TEEHardwareIntelSGX + 1

	teeInvalid  = "invalid"
	teeIntelSGX = "intel-sgx"
)

// String returns the string representation of a TEEHardware.
func (h TEEHardware) String() string {
	switch h {
	case TEEHardwareInvalid:
		return teeInvalid
	case TEEHardwareIntelSGX:
		return teeIntelSGX
	default:
		return "[unsupported TEEHardware]"
	}
}

// FromString deserializes a string into a TEEHardware.
func (h *TEEHardware) FromString(str string) error {
	switch strings.ToLower(str) {
	case "", teeInvalid:
		*h = TEEHardwareInvalid
	case teeIntelSGX:
		*h = TEEHardwareIntelSGX
	default:
		return ErrInvalidTEEHardware
	}

	return nil
}

// CapabilityTEE represents the node's TEE capability.
type CapabilityTEE struct {
	// TEE hardware type.
	Hardware TEEHardware `json:"hardware"`

	// Runtime attestation key.
	RAK signature.PublicKey `json:"rak"`

	// Attestation.
	Attestation []byte `json:"attestation"`
}

// HashRAK computes the expected report data hash bound to a given public RAK.
func HashRAK(rak signature.PublicKey) hash.Hash {
	hData := make([]byte, 0, len(teeHashContext)+signature.PublicKeySize)
	hData = append(hData, teeHashContext...)
	hData = append(hData, rak[:]...)
	return hash.NewFromBytes(hData)
}

// Verify verifies the node's TEE capabilities, at the provided timestamp and height.
func (c *CapabilityTEE) Verify(teeCfg *TEEFeatures, ts time.Time, height uint64, constraints []byte, nodeID signature.PublicKey) error {
	switch c.Hardware {
	case TEEHardwareIntelSGX:
		// Parse SGX remote attestation.
		var sa SGXAttestation
		if err := cbor.Unmarshal(c.Attestation, &sa); err != nil {
			return fmt.Errorf("node: malfomed SGX attestation: %w", err)
		}
		if err := sa.ValidateBasic(teeCfg); err != nil {
			return fmt.Errorf("node: malformed SGX attestation: %w", err)
		}

		// Parse SGX constraints.
		var sc SGXConstraints
		if err := cbor.Unmarshal(constraints, &sc); err != nil {
			return fmt.Errorf("node: malformed SGX constraints: %w", err)
		}
		if err := sc.ValidateBasic(teeCfg); err != nil {
			return fmt.Errorf("node: malformed SGX constraints: %w", err)
		}

		return sa.Verify(teeCfg, ts, height, &sc, c.RAK, nodeID)
	default:
		return ErrInvalidTEEHardware
	}
}

// String returns a string representation of itself.
func (n *Node) String() string {
	return "<Node id=" + n.ID.String() + ">"
}

// MultiSignedNode is a multi-signed blob containing a CBOR-serialized Node.
type MultiSignedNode struct {
	signature.MultiSigned
}

// Open first verifies the blob signatures and then unmarshals the blob.
func (s *MultiSignedNode) Open(context signature.Context, node *Node) error {
	return s.MultiSigned.Open(context, node)
}

// PrettyPrint writes a pretty-printed representation of the type
// to the given writer.
func (s MultiSignedNode) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	pt, err := s.PrettyType()
	if err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
		return
	}

	pt.(prettyprint.PrettyPrinter).PrettyPrint(ctx, prefix, w)
}

// PrettyType returns a representation of the type that can be used for pretty printing.
func (s MultiSignedNode) PrettyType() (interface{}, error) {
	var n Node
	if err := cbor.Unmarshal(s.MultiSigned.Blob, &n); err != nil {
		return nil, fmt.Errorf("malformed signed blob: %w", err)
	}
	return signature.NewPrettyMultiSigned(s.MultiSigned, n)
}

// MultiSignNode serializes the Node and multi-signs the result.
func MultiSignNode(signers []signature.Signer, context signature.Context, node *Node) (*MultiSignedNode, error) {
	multiSigned, err := signature.SignMultiSigned(signers, context, node)
	if err != nil {
		return nil, err
	}

	return &MultiSignedNode{
		MultiSigned: *multiSigned,
	}, nil
}
