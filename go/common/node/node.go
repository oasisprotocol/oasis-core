// Package node implements common node identity routines.
//
// This package is meant for interoperability with the rust compute worker.
package node

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/prettyprint"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/common/version"
)

var (
	// ErrInvalidTEEHardware is the error returned when a TEE hardware
	// implementation is invalid.
	ErrInvalidTEEHardware = errors.New("node: invalid TEE implementation")

	// ErrRAKHashMismatch is the error returned when the TEE attestation
	// does not contain the node's RAK hash.
	ErrRAKHashMismatch = errors.New("node: RAK hash mismatch")

	teeHashContext = []byte("oasis-core/node: TEE RAK binding")

	_ prettyprint.PrettyPrinter = (*SignedNode)(nil)
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
	ID common.Namespace `json:"id"`

	// Version is the version of the runtime.
	Version version.Version `json:"version"`

	// Capabilities are the node's capabilities for a given runtime.
	Capabilities Capabilities `json:"capabilities"`

	// ExtraInfo is the extra per node + per runtime opaque data associated
	// with the current instance.
	ExtraInfo []byte `json:"extra_info"`
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

// SignedNode is a signed blob containing a CBOR-serialized Node.
type SignedNode struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedNode) Open(context signature.Context, node *Node) error { // nolint: interfacer
	return s.Signed.Open(context, node)
}

// PrettyPrint writes a pretty-printed representation of the type
// to the given writer.
func (s SignedNode) PrettyPrint(prefix string, w io.Writer) {
	var n Node
	if err := cbor.Unmarshal(s.Signed.Blob, &n); err != nil {
		fmt.Fprintf(w, "%s<malformed: %s>\n", prefix, err)
		return
	}

	pp := signature.NewPrettySigned(s.Signed, n)
	pp.PrettyPrint(prefix, w)
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
