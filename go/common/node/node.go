// Package node implements common node identity routines.
//
// This package is meant for interoperability with the rust compute worker.
package node

import (
	"crypto/x509"
	"errors"
	"math"
	"net"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ethereum"
	pbCommon "github.com/oasislabs/ekiden/go/grpc/common"
)

var (
	// ErrInvalidAddress is the error returned when a transport address
	// is invalid.
	ErrInvalidAddress = errors.New("node: invalid transport address")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("node: Protobuf is nil")

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
	Addresses []net.Addr `codec:"addresses"`

	// Certificate is the certificate for establishing TLS connections.
	Certificate *Certificate `codec:"certificate"`

	// Stake is the node's stake. (TODO: Not defined yet.)
	Stake []byte `codec:"stake"`
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
		n.Addresses = make([]net.Addr, 0, len(pbAddresses))
		for _, v := range pbAddresses {
			addr, err := parseProtoAddress(v)
			if err != nil {
				return err
			}
			n.Addresses = append(n.Addresses, addr)
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

func parseProtoAddress(pb *pbCommon.Address) (net.Addr, error) {
	var ipLen int
	switch pb.GetTransport() {
	case pbCommon.Address_TCPv4:
		ipLen = 4
	case pbCommon.Address_TCPv6:
		ipLen = 16
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

	tAddr := new(net.TCPAddr)
	copy(tAddr.IP[:], rawIP)
	tAddr.Port = int(rawPort)

	return tAddr, nil
}

func toProtoAddress(addr net.Addr) *pbCommon.Address {
	taddr, ok := addr.(*net.TCPAddr)
	if !ok {
		panic("unsupported address type")
	}

	pbAddr := new(pbCommon.Address)
	ip := taddr.IP.To4()
	if ip != nil {
		pbAddr.Transport = pbCommon.Address_TCPv4
	} else {
		ip = taddr.IP.To16()
		if ip == nil {
			panic("IP address is neither IPv4 nor IPv6")
		}
		pbAddr.Transport = pbCommon.Address_TCPv6
	}
	pbAddr.Address = append([]byte{}, ip...)
	pbAddr.Port = uint32(taddr.Port)

	return pbAddr
}

func toProtoAddresses(addrs []net.Addr) []*pbCommon.Address {
	var pbAddrs []*pbCommon.Address
	for _, addr := range addrs {
		pbAddrs = append(pbAddrs, toProtoAddress(addr))
	}
	return pbAddrs
}
