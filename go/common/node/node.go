// Package node implements common node identity routines.
//
// This package is meant for interoperability with the rust compute worker.
package node

import (
	"crypto/x509"
	"errors"
	"math"
	"net"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ethereum"
	"github.com/oasislabs/ekiden/go/grpc/common"

	"github.com/ugorji/go/codec"
)

var (
	// ErrInvalidAddress is the error returned when a transport address
	// is invalid.
	ErrInvalidAddress = errors.New("node: invalid transport address")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("node: Protobuf is nil")
)

// Node represents public connectivity information about an Ekiden node.
type Node struct {
	// ID is the public key identifying the node.
	ID signature.PublicKey

	// EthAddress is the optional Ethereum address of this node.
	EthAddress *ethereum.Address

	// EntityID is the public key identifying the Entity controlling
	// the node.
	EntityID signature.PublicKey

	// Expiration is the epoch in which this node's commitment expires.
	Expiration uint64

	// Addresses is the list of addresses at which the node can be reached.
	Addresses []net.Addr

	// Certificate is the certificate for establishing TLS connections.
	Certificate *Certificate

	// Stake is the node's stake. (TODO: Not defined yet.)
	Stake []byte
}

// Certificate represents a X.509 certificate.
type Certificate struct {
	// Der is the DER encoding of a X.509 certificate.
	Der []byte
}

// Parse parses the DER encoded payload and returns the certificate.
func (c *Certificate) Parse() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.Der)
}

// FromProto deserializes a protobuf into a Node.
func (n *Node) FromProto(pb *common.Node) error { // nolint:gocyclo
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

	n.Addresses = make([]net.Addr, 0, len(pb.GetAddresses()))
	for _, v := range pb.GetAddresses() {
		addr, err := parseProtoAddress(v)
		if err != nil {
			return err
		}
		n.Addresses = append(n.Addresses, addr)
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
func (n *Node) ToProto() *common.Node {
	pb := new(common.Node)

	pb.Id, _ = n.ID.MarshalBinary()
	if n.EthAddress != nil {
		pb.EthAddress, _ = n.EthAddress.MarshalBinary()
	}
	pb.EntityId, _ = n.EntityID.MarshalBinary()
	pb.Expiration = n.Expiration
	pb.Addresses = toProtoAddresses(n.Addresses)
	if n.Certificate != nil {
		pb.Certificate = &common.Certificate{
			Der: append([]byte{}, n.Certificate.Der...),
		}
	}
	pb.Stake = append([]byte{}, n.Stake...)

	return pb
}

// ToSignable serialized the Node into a signature compatible byte vector.
func (n *Node) ToSignable() []byte {
	var b []byte
	enc := codec.NewEncoderBytes(&b, signature.CBORHandle)
	if err := enc.Encode(n); err != nil {
		panic(err)
	}

	return b
}

func parseProtoAddress(pb *common.Address) (net.Addr, error) {
	var ipLen int
	switch pb.GetTransport() {
	case common.Address_TCPv4:
		ipLen = 4
	case common.Address_TCPv6:
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

func toProtoAddress(addr net.Addr) *common.Address {
	taddr, ok := addr.(*net.TCPAddr)
	if !ok {
		panic("unsupported address type")
	}

	pbAddr := new(common.Address)
	ip := taddr.IP.To4()
	if ip != nil {
		pbAddr.Transport = common.Address_TCPv4
	} else {
		ip = taddr.IP.To16()
		if ip == nil {
			panic("IP address is neither IPv4 nor IPv6")
		}
		pbAddr.Transport = common.Address_TCPv6
	}
	pbAddr.Address = append([]byte{}, ip...)
	pbAddr.Port = uint32(taddr.Port)

	return pbAddr
}

func toProtoAddresses(addrs []net.Addr) []*common.Address {
	var pbAddrs []*common.Address
	for _, addr := range addrs {
		pbAddrs = append(pbAddrs, toProtoAddress(addr))
	}
	return pbAddrs
}
