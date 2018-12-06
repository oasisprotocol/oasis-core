// Package node implements common node identity routines.
//
// This package is meant for interoperability with the rust compute worker.
package node

import (
	"crypto/x509"
	"errors"
	"math"
	"time"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ethereum"
	"github.com/oasislabs/ekiden/go/common/ias"
	pbCommon "github.com/oasislabs/ekiden/go/grpc/common"
)

var (
	// ErrInvalidAddress is the error returned when a transport address
	// is invalid.
	ErrInvalidAddress = errors.New("node: invalid transport address")

	// ErrInvalidTEEHardware is the error returned when a TEE hardware
	// implementation is invalid.
	ErrInvalidTEEHardware = errors.New("node: invalid TEE implementation")

	// ErrRAKHashMismatch is the error returned when the TEE attestation
	// does not contain the node's RAK hash.
	ErrRAKHashMismatch = errors.New("node: RAK hash mismatch")

	// ErrInvalidAttestation is the error returned when the TEE attestation
	// is malformed.
	ErrInvalidAttestation = errors.New("node: invalid TEE attestation")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("node: Protobuf is nil")

	teeHashContext = []byte("EkNodReg")

	_ cbor.Marshaler   = (*Node)(nil)
	_ cbor.Unmarshaler = (*Node)(nil)
)

// Node represents public connectivity information about an Ekiden node.
type Node struct {
	// ID is the public key identifying the node.
	ID signature.PublicKey `codec:"id"`

	// EthAddress is the optional Ethereum address of this node.
	EthAddress *ethereum.Address `codec:"eth_address"`

	// EntityID is the public key identifying the Entity controlling
	// the node.
	EntityID signature.PublicKey `codec:"entity_id"`

	// Expiration is the epoch in which this node's commitment expires.
	Expiration uint64 `codec:"expiration"`

	// Addresses is the list of addresses at which the node can be reached.
	Addresses []Address `codec:"addresses"`

	// Certificate is the certificate for establishing TLS connections.
	Certificate *Certificate `codec:"certificate"`

	// Stake is the node's stake. (TODO: Not defined yet.)
	Stake []byte `codec:"stake"`

	// Time of registration.
	RegistrationTime uint64 `codec:"registration_time"`

	// Capabilities are the node's capabilities.
	Capabilities Capabilities `codec:"capabilities"`
}

// Address families.
const (
	AddressFamilyIPv4 = "V4"
	AddressFamilyIPv6 = "V6"
)

// Address is an IP address.
//
// This structure format is compatible with Rust's SocketAddr serialization.
type Address struct {
	_struct struct{} `codec:",toarray"` // nolint

	// Family is an address family.
	Family string

	// Tuple is a (ip, port) tuple.
	Tuple AddressTuple
}

// NewAddress creates a new address.
func NewAddress(family string, ip []byte, port uint16) (*Address, error) {
	return &Address{
		Family: family,
		Tuple: AddressTuple{
			IP:   ip,
			Port: port,
		},
	}, nil
}

// AddressTuple is an (ip, port) tuple.
//
// This structure format is compatible with Rust's SocketAddr serialization.
type AddressTuple struct {
	_struct struct{} `codec:",toarray"` // nolint

	// IP address.
	IP []byte

	// Port.
	Port uint16
}

// Certificate represents a X.509 certificate.
type Certificate struct {
	// Der is the DER encoding of a X.509 certificate.
	Der []byte `codec:"der"`
}

// Parse parses the DER encoded payload and returns the certificate.
func (c *Certificate) Parse() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.Der)
}

// Capabilities represents a node's capabilities.
type Capabilities struct {
	// TEE is the capability of a node executing batches in a TEE.
	TEE *CapabilityTEE `codec:"tee,omitempty"`
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
	TEEHardwareInvalid  TEEHardware = 0
	TEEHardwareIntelSGX TEEHardware = 1
)

// CapabilityTEE represents the node's TEE capability.
type CapabilityTEE struct {
	// TEE hardware type.
	Hardware TEEHardware `codec:"hardware"`

	// Runtime attestation key.
	RAK signature.PublicKey `codec:"rak"`

	// Attestation.
	Attestation []byte `codec:"attestation"`
}

func (c *CapabilityTEE) fromProto(pb *pbCommon.CapabilitiesTEE) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	switch pb.GetHardware() {
	case pbCommon.CapabilitiesTEE_IntelSGX:
		c.Hardware = TEEHardwareIntelSGX
	default:
		return ErrInvalidTEEHardware
	}

	if err := c.RAK.UnmarshalBinary(pb.GetRak()); err != nil {
		return err
	}

	c.Attestation = pb.GetAttestation()

	return nil
}

func (c *CapabilityTEE) toProto() *pbCommon.CapabilitiesTEE {
	pb := new(pbCommon.CapabilitiesTEE)

	switch c.Hardware {
	case TEEHardwareIntelSGX:
		pb.Hardware = pbCommon.CapabilitiesTEE_IntelSGX
	default:
		panic(ErrInvalidTEEHardware)
	}

	pb.Rak, _ = c.RAK.MarshalBinary()

	if c.Attestation != nil {
		pb.Attestation = append([]byte{}, c.Attestation...)
	}

	return pb
}

// Verify verifies the node's TEE capabilities, at the provided timestamp.
func (c *CapabilityTEE) Verify(ts time.Time) error {
	var rakHash hash.Hash
	hData := make([]byte, 0, len(teeHashContext)+signature.PublicKeySize)
	hData = append(hData, teeHashContext...)
	hData = append(hData, c.RAK[:]...)
	rakHash.FromBytes(hData)

	switch c.Hardware {
	case TEEHardwareIntelSGX:
		var avrBundle ias.AVRBundle
		if err := avrBundle.UnmarshalCBOR(c.Attestation); err != nil {
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

		var acc byte
		for _, v := range q.Report.ReportData[hash.Size:] {
			acc |= v
		}
		if acc != 0 {
			return ErrInvalidAttestation
		}

		return nil
	default:
		return ErrInvalidTEEHardware
	}
}

// String returns a string representation of itself.
func (n *Node) String() string {
	return "<Node id=" + n.ID.String() + ">"
}

// Clone returns a copy of itself.
func (n *Node) Clone() common.Cloneable {
	nodeCopy := *n
	return &nodeCopy
}

// FromProto deserializes a protobuf into a Node.
func (n *Node) FromProto(pb *pbCommon.Node) error { // nolint:gocyclo
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := n.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	if b := pb.GetEthAddress(); b != nil {
		n.EthAddress = new(ethereum.Address)
		if err := n.EthAddress.UnmarshalBinary(b); err != nil {
			return err
		}
	}

	if err := n.EntityID.UnmarshalBinary(pb.GetEntityId()); err != nil {
		return err
	}

	n.Expiration = pb.GetExpiration()

	if pbAddresses := pb.GetAddresses(); pbAddresses != nil {
		n.Addresses = make([]Address, 0, len(pbAddresses))
		for _, v := range pbAddresses {
			addr, err := parseProtoAddress(v)
			if err != nil {
				return err
			}
			n.Addresses = append(n.Addresses, *addr)
		}
	}

	if pbCert := pb.GetCertificate(); pbCert != nil {
		n.Certificate = &Certificate{
			Der: append([]byte{}, pbCert.GetDer()...),
		}
	}

	if b := pb.GetStake(); b != nil {
		n.Stake = append([]byte{}, b...) // Copy
	}

	n.RegistrationTime = pb.GetRegistrationTime()

	if pbCapa := pb.GetCapabilities(); pbCapa != nil {
		if err := n.Capabilities.fromProto(pbCapa); err != nil {
			return err
		}
	}

	return nil
}

// ToProto serializes the Node into a protobuf.
func (n *Node) ToProto() *pbCommon.Node {
	pb := new(pbCommon.Node)

	pb.Id, _ = n.ID.MarshalBinary()
	if n.EthAddress != nil {
		pb.EthAddress, _ = n.EthAddress.MarshalBinary()
	}
	pb.EntityId, _ = n.EntityID.MarshalBinary()
	pb.Expiration = n.Expiration
	if n.Addresses != nil {
		pb.Addresses = toProtoAddresses(n.Addresses)
	}
	if n.Certificate != nil {
		pb.Certificate = &pbCommon.Certificate{
			Der: append([]byte{}, n.Certificate.Der...),
		}
	}
	if n.Stake != nil {
		pb.Stake = append([]byte{}, n.Stake...)
	}
	pb.RegistrationTime = n.RegistrationTime
	pb.Capabilities = new(pbCommon.Capabilities)
	if n.Capabilities.TEE != nil {
		pb.Capabilities.Tee = n.Capabilities.TEE.toProto()
	}

	return pb
}

// ToSignable serialized the Node into a signature compatible byte vector.
func (n *Node) ToSignable() []byte {
	return n.MarshalCBOR()
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (n *Node) MarshalCBOR() []byte {
	return cbor.Marshal(n)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (n *Node) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, n)
}

// SignedNode is a signed blob containing a CBOR-serialized Node.
type SignedNode struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedNode) Open(context []byte, node *Node) error { // nolint: interfacer
	return s.Signed.Open(context, node)
}

func parseProtoAddress(pb *pbCommon.Address) (*Address, error) {
	var ipLen int
	var family string
	switch pb.GetTransport() {
	case pbCommon.Address_TCPv4:
		ipLen = 4
		family = AddressFamilyIPv4
	case pbCommon.Address_TCPv6:
		ipLen = 16
		family = AddressFamilyIPv6
	default:
		return nil, ErrInvalidAddress
	}
	rawIP := pb.GetAddress()
	if len(rawIP) != ipLen {
		return nil, ErrInvalidAddress
	}

	rawPort := pb.GetPort()
	if rawPort > math.MaxUint16 {
		return nil, ErrInvalidAddress
	}

	return NewAddress(family, rawIP, uint16(rawPort))
}

func toProtoAddress(addr Address) *pbCommon.Address {
	pbAddr := new(pbCommon.Address)
	switch addr.Family {
	case AddressFamilyIPv4:
		pbAddr.Transport = pbCommon.Address_TCPv4
	case AddressFamilyIPv6:
		pbAddr.Transport = pbCommon.Address_TCPv6
	default:
		panic("Address is neither IPv4 nor IPv6")
	}
	pbAddr.Address = append([]byte{}, addr.Tuple.IP...)
	pbAddr.Port = uint32(addr.Tuple.Port)

	return pbAddr
}

func toProtoAddresses(addrs []Address) []*pbCommon.Address {
	var pbAddrs []*pbCommon.Address
	for _, addr := range addrs {
		pbAddrs = append(pbAddrs, toProtoAddress(addr))
	}
	return pbAddrs
}
