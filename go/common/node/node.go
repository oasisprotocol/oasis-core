// Package node implements common node identity routines.
//
// This package is meant for interoperability with the rust compute worker.
package node

import (
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/common/version"
	pbCommon "github.com/oasislabs/oasis-core/go/grpc/common"
)

var (
	// ErrInvalidTEEHardware is the error returned when a TEE hardware
	// implementation is invalid.
	ErrInvalidTEEHardware = errors.New("node: invalid TEE implementation")

	// ErrRAKHashMismatch is the error returned when the TEE attestation
	// does not contain the node's RAK hash.
	ErrRAKHashMismatch = errors.New("node: RAK hash mismatch")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("node: Protobuf is nil")

	teeHashContext = []byte("oasis-core/node: TEE RAK binding")
)

// Node represents public connectivity information about an Oasis node.
type Node struct {
	// ID is the public key identifying the node.
	ID signature.PublicKey `json:"id"`

	// EntityID is the public key identifying the Entity controlling
	// the node.
	EntityID signature.PublicKey `json:"entity_id"`

	// Expiration is the epoch in which this node's commitment expires.
	Expiration uint64 `json:"expiration"`

	// Committee contains information for connecting to this node as a committee
	// member.
	Committee CommitteeInfo `json:"committee"`

	// P2P contains information for connecting to this node via P2P transport.
	P2P P2PInfo `json:"p2p"`

	// Consensus contains information for connecting to this node as a
	// consensus member.
	Consensus ConsensusInfo `json:"consensus"`

	// Runtimes are the node's runtimes.
	Runtimes []*Runtime `json:"runtimes"`

	// Roles is a bitmask representing the node roles.
	Roles RolesMask `json:"roles"`
}

// RolesMask is Oasis node roles bitmask.
type RolesMask uint32

const (
	// RoleComputeWorker is Oasis compute worker role.
	RoleComputeWorker RolesMask = 1 << 0
	// RoleStorageWorker is Oasis storage worker role.
	RoleStorageWorker RolesMask = 1 << 1
	// RoleTransactionScheduler is Oasis transaction scheduler role.
	RoleTransactionScheduler RolesMask = 1 << 2
	// RoleKeyManager is the Oasis key manager role.
	RoleKeyManager RolesMask = 1 << 3
	// RoleMergeWorker is the Oasis merge worker role.
	RoleMergeWorker RolesMask = 1 << 4
	// RoleValidator is the Oasis validator role.
	RoleValidator RolesMask = 1 << 5

	// RoleReserved are all the bits of the Oasis node roles bitmask
	// that are reserved and must not be used.
	RoleReserved RolesMask = ((1 << 32) - 1) & ^((RoleValidator << 1) - 1)
)

func (m RolesMask) String() string {
	if m&RoleReserved != 0 {
		return "[invalid roles]"
	}

	var ret []string
	if m&RoleComputeWorker != 0 {
		ret = append(ret, "compute")
	}
	if m&RoleStorageWorker != 0 {
		ret = append(ret, "storage")
	}
	if m&RoleTransactionScheduler != 0 {
		ret = append(ret, "txn_scheduler")
	}
	if m&RoleKeyManager != 0 {
		ret = append(ret, "key_manager")
	}
	if m&RoleMergeWorker != 0 {
		ret = append(ret, "merge")
	}
	if m&RoleValidator != 0 {
		ret = append(ret, "validator")
	}

	return strings.Join(ret, ",")
}

// AddRoles adds the Node roles
func (n *Node) AddRoles(r RolesMask) {
	n.Roles |= r
}

// HasRoles checks if Node has roles
func (n *Node) HasRoles(r RolesMask) bool {
	return n.Roles&r != 0
}

// IsExpired returns true if the node expiration epoch is strictly smaller
// than the passed (current) epoch.
func (n *Node) IsExpired(epoch uint64) bool {
	return n.Expiration < epoch
}

// Runtime represents the runtimes supported by a given Oasis node.
type Runtime struct {
	// ID is the public key identifying the runtime.
	ID signature.PublicKey `json:"id"`

	// Version is the version of the runtime.
	Version version.Version `json:"version"`

	// Capabilities are the node's capabilities for a given runtime.
	Capabilities Capabilities `json:"capabilities"`

	// ExtraInfo is the extra per node + per runtime opaque data associated
	// with the current instance.
	ExtraInfo []byte `json:"extra_info"`
}

func (r *Runtime) fromProto(pb *pbCommon.NodeRuntime) error {
	if err := r.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	if pbCapa := pb.GetCapabilities(); pbCapa != nil {
		if err := r.Capabilities.fromProto(pbCapa); err != nil {
			return err
		}
	}

	r.ExtraInfo = pb.GetExtraInfo()
	r.Version = version.FromU64(pb.GetVersion())

	return nil
}

func (r *Runtime) toProto() *pbCommon.NodeRuntime {
	pb := new(pbCommon.NodeRuntime)

	pb.Id, _ = r.ID.MarshalBinary()

	pb.Capabilities = new(pbCommon.Capabilities)
	if r.Capabilities.TEE != nil {
		pb.Capabilities.Tee = r.Capabilities.TEE.toProto()
	}

	pb.ExtraInfo = r.ExtraInfo
	pb.Version = r.Version.ToU64()

	return pb
}

// CommitteInfo contains information for connecting to this node as a
// committee member.
type CommitteeInfo struct {
	// Certificate is the certificate for establishing TLS connections.
	Certificate []byte `json:"certificate"`

	// Addresses is the list of addresses at which the node can be reached.
	Addresses []Address `json:"addresses"`
}

// ParseCertificate returns the parsed x509 certificate.
func (info *CommitteeInfo) ParseCertificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(info.Certificate)
}

func (info *CommitteeInfo) toProto() *pbCommon.CommitteeInfo {
	pb := new(pbCommon.CommitteeInfo)

	pb.Certificate = info.Certificate
	pb.Addresses = ToProtoAddresses(info.Addresses)

	return pb
}

func (info *CommitteeInfo) fromProto(pb *pbCommon.CommitteeInfo) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	info.Certificate = pb.GetCertificate()

	if pbAddresses := pb.GetAddresses(); pbAddresses != nil {
		info.Addresses = make([]Address, 0, len(pbAddresses))
		for _, v := range pbAddresses {
			addr, err := parseProtoAddress(v)
			if err != nil {
				return err
			}
			info.Addresses = append(info.Addresses, *addr)
		}
	}

	return nil
}

// P2PInfo contains information for connecting to this node via P2P transport.
type P2PInfo struct {
	// ID is the unique identifier of the node on the P2P transport.
	ID signature.PublicKey `json:"id"`

	// Addresses is the list of addresses at which the node can be reached.
	Addresses []Address `json:"addresses"`
}

func (info *P2PInfo) toProto() *pbCommon.P2PInfo {
	pb := new(pbCommon.P2PInfo)

	pb.Id, _ = info.ID.MarshalBinary()
	pb.Addresses = ToProtoAddresses(info.Addresses)

	return pb
}

func (info *P2PInfo) fromProto(pb *pbCommon.P2PInfo) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := info.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	if pbAddresses := pb.GetAddresses(); pbAddresses != nil {
		info.Addresses = make([]Address, 0, len(pbAddresses))
		for _, v := range pbAddresses {
			addr, err := parseProtoAddress(v)
			if err != nil {
				return err
			}
			info.Addresses = append(info.Addresses, *addr)
		}
	}

	return nil
}

// ConsensusInfo contains information for connecting to this node as a
// consensus member.
type ConsensusInfo struct {
	// ID is the unique identifier of the node as a consensus member.
	ID signature.PublicKey `json:"id"`

	// Addresses is the list of addresses at which the node can be reached.
	Addresses []ConsensusAddress `json:"addresses"`
}

func (info *ConsensusInfo) toProto() *pbCommon.ConsensusInfo {
	pb := new(pbCommon.ConsensusInfo)
	pb.Id, _ = info.ID.MarshalBinary()
	pb.Addresses = ToProtoConsensusAddresses(info.Addresses)
	return pb
}

func (info *ConsensusInfo) fromProto(pb *pbCommon.ConsensusInfo) error {
	if err := info.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	if pbConsensusAddrs := pb.GetAddresses(); pbConsensusAddrs != nil {
		consensusAddrs, err := FromProtoConsensusAddresses(pbConsensusAddrs)
		if err != nil {
			return err
		}
		info.Addresses = consensusAddrs
	}

	return nil
}

// Capabilities represents a node's capabilities.
type Capabilities struct {
	// TEE is the capability of a node executing batches in a TEE.
	TEE *CapabilityTEE `json:"tee,omitempty"`
}

func (c *Capabilities) fromProto(pb *pbCommon.Capabilities) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if pbTee := pb.GetTee(); pbTee != nil {
		c.TEE = new(CapabilityTEE)
		if err := c.TEE.fromProto(pbTee); err != nil {
			return err
		}
	}

	return nil
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

// FromProto deserializes a protobuf into a TEEHardware.
func (h *TEEHardware) FromProto(pb pbCommon.CapabilitiesTEE_Hardware) error {
	switch pb {
	case pbCommon.CapabilitiesTEE_Invalid:
		*h = TEEHardwareInvalid
	case pbCommon.CapabilitiesTEE_IntelSGX:
		*h = TEEHardwareIntelSGX
	default:
		return ErrInvalidTEEHardware
	}
	return nil
}

// ToProto serializes a TEEHardware into a protobuf.
func (h *TEEHardware) ToProto() (pbCommon.CapabilitiesTEE_Hardware, error) {
	switch *h {
	case TEEHardwareInvalid:
		return pbCommon.CapabilitiesTEE_Invalid, nil
	case TEEHardwareIntelSGX:
		return pbCommon.CapabilitiesTEE_IntelSGX, nil
	default:
		return pbCommon.CapabilitiesTEE_Invalid, ErrInvalidTEEHardware
	}
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

func (c *CapabilityTEE) fromProto(pb *pbCommon.CapabilitiesTEE) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := c.Hardware.FromProto(pb.GetHardware()); err != nil {
		return err
	}

	if err := c.RAK.UnmarshalBinary(pb.GetRak()); err != nil {
		return err
	}

	c.Attestation = pb.GetAttestation()

	return nil
}

func (c *CapabilityTEE) toProto() *pbCommon.CapabilitiesTEE {
	pb := new(pbCommon.CapabilitiesTEE)

	var err error
	if pb.Hardware, err = c.Hardware.ToProto(); err != nil {
		panic(err)
	}

	pb.Rak, _ = c.RAK.MarshalBinary()

	if c.Attestation != nil {
		pb.Attestation = append([]byte{}, c.Attestation...)
	}

	return pb
}

// RAKHash computes the expected AVR report hash bound to a given public RAK.
func RAKHash(rak signature.PublicKey) hash.Hash {
	var rakHash hash.Hash
	hData := make([]byte, 0, len(teeHashContext)+signature.PublicKeySize)
	hData = append(hData, teeHashContext...)
	hData = append(hData, rak[:]...)
	rakHash.FromBytes(hData)
	return rakHash
}

// Verify verifies the node's TEE capabilities, at the provided timestamp.
func (c *CapabilityTEE) Verify(ts time.Time) error {
	rakHash := RAKHash(c.RAK)

	switch c.Hardware {
	case TEEHardwareIntelSGX:
		var avrBundle ias.AVRBundle
		if err := cbor.Unmarshal(c.Attestation, &avrBundle); err != nil {
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

		// Ensure that the ISV quote includes the hash of the node's
		// RAK.
		var avrRAKHash hash.Hash
		_ = avrRAKHash.UnmarshalBinary(q.Report.ReportData[:hash.Size])
		if !rakHash.Equal(&avrRAKHash) {
			return ErrRAKHashMismatch
		}

		// The last 32 bytes of the quote ReportData are deliberately
		// ignored.

		return nil
	default:
		return ErrInvalidTEEHardware
	}
}

// String returns a string representation of itself.
func (n *Node) String() string {
	return "<Node id=" + n.ID.String() + ">"
}

// FromProto deserializes a protobuf into a Node.
func (n *Node) FromProto(pb *pbCommon.Node) error { // nolint:gocyclo
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := n.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	if err := n.EntityID.UnmarshalBinary(pb.GetEntityId()); err != nil {
		return err
	}

	n.Expiration = pb.GetExpiration()

	if err := n.Committee.fromProto(pb.GetCommittee()); err != nil {
		return err
	}

	if err := n.P2P.fromProto(pb.GetP2P()); err != nil {
		return err
	}

	if err := n.Consensus.fromProto(pb.GetConsensus()); err != nil {
		return err
	}

	if pbRuntimes := pb.GetRuntimes(); pbRuntimes != nil {
		n.Runtimes = make([]*Runtime, 0, len(pbRuntimes))
		for _, v := range pbRuntimes {
			rt := new(Runtime)
			if err := rt.fromProto(v); err != nil {
				return err
			}
			n.Runtimes = append(n.Runtimes, rt)
		}
	}

	n.Roles = RolesMask(pb.GetRoles())

	return nil
}

// ToProto serializes the Node into a protobuf.
func (n *Node) ToProto() *pbCommon.Node {
	pb := new(pbCommon.Node)

	pb.Id, _ = n.ID.MarshalBinary()
	pb.EntityId, _ = n.EntityID.MarshalBinary()
	pb.Expiration = n.Expiration
	pb.Committee = n.Committee.toProto()
	pb.P2P = n.P2P.toProto()
	pb.Consensus = n.Consensus.toProto()
	if n.Runtimes != nil {
		pb.Runtimes = make([]*pbCommon.NodeRuntime, 0, len(n.Runtimes))
		for _, v := range n.Runtimes {
			pb.Runtimes = append(pb.Runtimes, v.toProto())
		}
	}

	pb.Roles = uint32(n.Roles)

	return pb
}

// SignedNode is a signed blob containing a CBOR-serialized Node.
type SignedNode struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedNode) Open(context signature.Context, node *Node) error { // nolint: interfacer
	return s.Signed.Open(context, node)
}

// SignNode serializes the Node and signs the result.
func SignNode(signer signature.Signer, context signature.Context, node *Node) (*SignedNode, error) {
	signed, err := signature.SignSigned(signer, context, node)
	if err != nil {
		return nil, err
	}

	return &SignedNode{
		Signed: *signed,
	}, nil
}
