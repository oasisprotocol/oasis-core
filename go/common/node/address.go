package node

import (
	"encoding"
	"errors"
	"math"
	"net"

	pbCommon "github.com/oasislabs/ekiden/go/grpc/common"
)

var (
	// ErrInvalidAddress is the error returned when a transport address is
	// invalid.
	ErrInvalidAddress = errors.New("node: invalid transport address")

	_ encoding.TextMarshaler   = (*Address)(nil)
	_ encoding.TextUnmarshaler = (*Address)(nil)
)

// Address represents a TCP address for the purpose of node descriptors.
type Address struct {
	net.TCPAddr
}

// MarshalText implements the encoding.TextMarshaler interface.
func (a *Address) MarshalText() ([]byte, error) {
	return []byte(a.TCPAddr.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (a *Address) UnmarshalText(text []byte) error {
	tcpAddr, err := net.ResolveTCPAddr("", string(text))
	if err != nil {
		return err
	}

	a.TCPAddr = *tcpAddr

	return nil
}

// FromIP populates the address from a net.IP and port.
func (a *Address) FromIP(ip net.IP, port uint16) error {
	if ipv4 := ip.To4(); ipv4 != nil {
		a.IP = ipv4
	} else if ipv6 := ip.To16(); ipv6 != nil {
		a.IP = ipv6
	} else {
		return ErrInvalidAddress
	}

	a.Port = int(port)
	a.Zone = ""

	return nil
}

// ToProtoAddresses converts a list of Addresses to protocol buffers.
func ToProtoAddresses(addrs []Address) []*pbCommon.Address {
	var pbAddrs []*pbCommon.Address
	for _, addr := range addrs {
		pbAddrs = append(pbAddrs, toProtoAddress(addr))
	}
	return pbAddrs
}

func parseProtoAddress(pb *pbCommon.Address) (*Address, error) {
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

	inner := net.TCPAddr{
		IP:   net.IP(rawIP),
		Port: int(rawPort),
	}

	return &Address{inner}, nil
}

func toProtoAddress(addr Address) *pbCommon.Address {
	pbAddr := new(pbCommon.Address)
	var rawIP []byte
	if rawIP = addr.IP.To4(); rawIP != nil {
		pbAddr.Transport = pbCommon.Address_TCPv4
	} else if rawIP = addr.IP.To16(); rawIP != nil {
		pbAddr.Transport = pbCommon.Address_TCPv6
	} else {
		panic("node: address is neither IPv4 nor IPv6")
	}

	pbAddr.Address = append([]byte{}, rawIP...)
	pbAddr.Port = uint32(addr.Port)

	return pbAddr
}
