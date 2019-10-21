package node

import (
	"encoding"
	"errors"
	"math"
	"net"

	pbCommon "github.com/oasislabs/oasis-core/go/grpc/common"
)

var (
	// ErrInvalidAddress is the error returned when a transport address is
	// invalid.
	ErrInvalidAddress = errors.New("node: invalid transport address")

	unroutableNetworks []net.IPNet

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

// IsRoutable returns true iff the address is likely to be globally routable.
func (a *Address) IsRoutable() bool {
	for _, v := range unroutableNetworks {
		if v.Contains(a.IP) {
			return false
		}
	}
	return true
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

func init() {
	// List taken from RFC 6890.  This is different from what tendermint
	// does (more restrictive).
	for _, v := range []string{
		"0.0.0.0/8",          // RFC 1122
		"10.0.0.0/8",         // RFC 1918: Private-Use
		"100.64.0.0/10",      // RFC 6598: Shared Address Space
		"127.0.0.0/8",        // RFC 1122: Loopback
		"169.254.0.0/16",     // RFC 3927: Link Local
		"172.16.0.0/12",      // RFC 1918: Private-Use
		"192.0.0.0/24",       // RFC 6890
		"192.0.0.0/29",       // RFC 6333: DS-Lite
		"192.0.2.0/24",       // RFC 5737: Documentation (TEST-NET-1)
		"192.168.0.0/16",     // RFC 1918: Private-Use
		"192.18.0.0/15",      // RFC 2544: Benchmarking
		"198.51.100.0/24",    // RFC 5737: TEST-NET-2
		"203.0.113.0/24",     // RFC 5737: TEST-NET-3
		"240.0.0.0/4",        // RFC 1112: Reserved
		"255.255.255.255/32", // RFC 919: Limited Broadcast
		"::1/128",            // RFC 4291: Loopback Address
		"::/128",             // RFC 4291: Unspecified Address
		"100::/64",           // RFC 6666: Discard-Only Address Block
		"2001::/32",          // RFC 4380: TEREDO
		"2001:2::/48",        // RFC 5180: Benchmarking
		"2001:db8::/32",      // RFC 3849: Documentation
		"2001:10::/28",       // RFC 4843: ORCHID
		"2002::/16",          // RFC 3056: 6to4
		"fc00::/7",           // RFC 4193: Unique-Local
		"fe80::/10",          // RFC 4291: Linked-Scoped Unicast
	} {
		_, ipNet, err := net.ParseCIDR(v)
		if err != nil {
			panic("node: failed to parse reserved net: " + err.Error())
		}
		unroutableNetworks = append(unroutableNetworks, *ipNet)
	}
}
