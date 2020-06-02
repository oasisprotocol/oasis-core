package node

import (
	"encoding"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

var (
	// ErrInvalidAddress is the error returned when a transport address is
	// invalid.
	ErrInvalidAddress = errors.New("node: invalid transport address")
	// ErrConsensusAddressNoID is the error returned when a consensus address
	// doesn't have the ID@ part.
	ErrConsensusAddressNoID = errors.New("node: consensus address doesn't have ID@ part")
	// ErrTLSAddressNoPubKey is the error returned when a TLS address doesn't have the PubKey@ part.
	ErrTLSAddressNoPubKey = errors.New("node: TLS address missing PubKey@ part")

	unroutableNetworks []net.IPNet

	_ encoding.TextMarshaler   = (*Address)(nil)
	_ encoding.TextUnmarshaler = (*Address)(nil)
	_ encoding.TextMarshaler   = (*ConsensusAddress)(nil)
	_ encoding.TextUnmarshaler = (*ConsensusAddress)(nil)
)

// Address represents a TCP address for the purpose of node descriptors.
type Address struct {
	net.TCPAddr
}

// Equal compares vs another address for equality.
func (a *Address) Equal(other *Address) bool {
	if !a.IP.Equal(other.IP) {
		return false
	}
	if a.Port != other.Port {
		return false
	}
	if a.Zone != other.Zone {
		return false
	}
	return true
}

// MarshalText implements the encoding.TextMarshaler interface.
func (a *Address) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
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

// String returns the string representation of an address.
func (a Address) String() string {
	return a.TCPAddr.String()
}

// ConsensusAddress represents a Tendermint consensus address that includes an
// ID and a TCP address.
// NOTE: The consensus address ID could be different from the consensus ID
// to allow using a sentry node's ID and address instead of the validator's.
type ConsensusAddress struct {
	// ID is public key identifying the node.
	ID signature.PublicKey `json:"id"`
	// Address is the address at which the node can be reached.
	Address Address `json:"address"`
}

// MarshalText implements the encoding.TextMarshaler interface.
func (ca *ConsensusAddress) MarshalText() ([]byte, error) {
	idStr := ca.ID.String()
	addrStr, err := ca.Address.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("node: error marshalling consensus address' TCP address: %w", err)
	}
	return []byte(fmt.Sprintf("%s@%s", idStr, addrStr)), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (ca *ConsensusAddress) UnmarshalText(text []byte) error {
	spl := strings.Split(string(text), "@")
	if len(spl) != 2 {
		return ErrConsensusAddressNoID
	}
	if err := ca.ID.UnmarshalText([]byte(spl[0])); err != nil {
		return fmt.Errorf("node: unable to parse consensus address' ID: %w", err)
	}
	if err := ca.Address.UnmarshalText([]byte(spl[1])); err != nil {
		return fmt.Errorf("node: unable to parse consensus address' TCP address: %w", err)
	}
	return nil
}

// String returns a string representation of a consensus address.
func (ca *ConsensusAddress) String() string {
	return fmt.Sprintf("%s@%s", ca.ID, ca.Address)
}

// TLSAddress represents an Oasis committee address that includes a TLS public key and a TCP
// address.
//
// NOTE: The address TLS public key can be different from the actual node TLS public key to allow
// using a sentry node's addresses.
type TLSAddress struct {
	// PubKey is the public key used for establishing TLS connections.
	PubKey signature.PublicKey `json:"pub_key"`

	// Address is the address at which the node can be reached.
	Address Address `json:"address"`
}

// Equal compares vs another TLSAddress for equality.
func (ta *TLSAddress) Equal(other *TLSAddress) bool {
	if !ta.PubKey.Equal(other.PubKey) {
		return false
	}
	if !ta.Address.Equal(&other.Address) {
		return false
	}
	return true
}

// MarshalText implements the encoding.TextMarshaler interface.
func (ta *TLSAddress) MarshalText() ([]byte, error) {
	pubKeyStr, err := ta.PubKey.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("node: error marshalling TLS address' public key: %w", err)
	}
	addrStr, err := ta.Address.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("node: error marshalling TLS address' TCP address: %w", err)
	}
	return []byte(fmt.Sprintf("%s@%s", pubKeyStr, addrStr)), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (ta *TLSAddress) UnmarshalText(text []byte) error {
	spl := strings.Split(string(text), "@")
	if len(spl) != 2 {
		return ErrTLSAddressNoPubKey
	}
	if err := ta.PubKey.UnmarshalText([]byte(spl[0])); err != nil {
		return fmt.Errorf("node: unable to parse TLS address' public key: %w", err)
	}
	if err := ta.Address.UnmarshalText([]byte(spl[1])); err != nil {
		return fmt.Errorf("node: unable to parse TLS address' TCP address: %w", err)
	}
	return nil
}

// String returns a string representation of a TLS address.
func (ta *TLSAddress) String() string {
	return ta.Address.String()
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
