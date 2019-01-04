// Package node implements common node identity routines.
//
// This package is meant for interoperability with the rust compute worker.
package node

import (
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"math"
	"net"
	"time"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
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

	// P2P contains information for connecting to this node via P2P transport.
	P2P P2PInfo `codec:"p2p"`

	// Certificate is the certificate for establishing TLS connections.
	Certificate *Certificate `codec:"certificate"`

	// Time of registration.
	RegistrationTime uint64 `codec:"registration_time"`

	// Runtimes are the node's runtimes.
	Runtimes []*Runtime `codec:"runtimes"`
}

// Runtime represents the runtimes supported by a given Ekiden node.
type Runtime struct {
	// ID is the public key identifying the runtime.
	ID signature.PublicKey `codec:"id"`

	// Capabilities are the node's capabilities for a given runtime.
	Capabilities Capabilities `codec:"capabilities"`
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

	return nil
}

func (r *Runtime) toProto() *pbCommon.NodeRuntime {
	pb := new(pbCommon.NodeRuntime)

	pb.Id, _ = r.ID.MarshalBinary()

	pb.Capabilities = new(pbCommon.Capabilities)
	if r.Capabilities.TEE != nil {
		pb.Capabilities.Tee = r.Capabilities.TEE.toProto()
	}

	return pb
}

// P2PInfo contains information for connecting to this node via P2P transport.
type P2PInfo struct {
	// ID is the unique identifier of the node on the P2P transport.
	ID []byte `codec:"id"`

	// Addresses is the list of multiaddrs at which the node can be reached.
	Addresses [][]byte `codec:"addresses"`
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

// FromIP populates the address from a net.IP and port.
func (a *Address) FromIP(ip net.IP, port uint16) error {
	if ipv4 := ip.To4(); ipv4 != nil {
		a.Family = AddressFamilyIPv4
		a.Tuple.IP = ipv4
	} else if ipv6 := ip.To16(); ipv6 != nil {
		a.Family = AddressFamilyIPv6
		a.Tuple.IP = ipv6
	} else {
		return errors.New("unknown address family")
	}

	a.Tuple.Port = port

	return nil
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
	// DER is the DER encoding of a X.509 certificate.
	DER []byte `codec:"der"`
}

// Parse parses the DER encoded payload and returns the certificate.
func (c *Certificate) Parse() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.DER)
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
	hData := make([]byte, 0, len(teeHashContext)+signature.PublicKeySize)
	hData = append(hData, teeHashContext...)
	hData = append(hData, c.RAK[:]...)
	rakHash := sha512.Sum512(hData)

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
		if subtle.ConstantTimeCompare(rakHash[:], q.Report.ReportData[:]) != 1 {
			return ErrRAKHashMismatch
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
			DER: append([]byte{}, pbCert.GetDer()...),
		}
	}

	n.RegistrationTime = pb.GetRegistrationTime()

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
			Der: append([]byte{}, n.Certificate.DER...),
		}
	}
	pb.RegistrationTime = n.RegistrationTime
	if n.Runtimes != nil {
		pb.Runtimes = make([]*pbCommon.NodeRuntime, 0, len(n.Runtimes))
		for _, v := range n.Runtimes {
			pb.Runtimes = append(pb.Runtimes, v.toProto())
		}
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

// SignNode serializes the Node and signs the result.
func SignNode(privateKey signature.PrivateKey, context []byte, node *Node) (*SignedNode, error) {
	signed, err := signature.SignSigned(privateKey, context, node)
	if err != nil {
		return nil, err
	}

	return &SignedNode{
		Signed: *signed,
	}, nil
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
