package node

import (
	"encoding"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common"
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

	_ encoding.TextMarshaler   = (*Address)(nil)
	_ encoding.TextUnmarshaler = (*Address)(nil)
	_ encoding.TextMarshaler   = (*ConsensusAddress)(nil)
	_ encoding.TextUnmarshaler = (*ConsensusAddress)(nil)
)

// Address represents a TCP address for the purpose of node descriptors.
type Address struct {
	IP   net.IP `json:"IP"`
	Port int64  `json:"Port"`
	Zone string `json:"Zone"`
}

// ToTCPAddr returns a net TCP address.
func (a *Address) ToTCPAddr() *net.TCPAddr {
	return &net.TCPAddr{
		IP:   a.IP,
		Port: int(a.Port),
		Zone: a.Zone,
	}
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

	a.IP = tcpAddr.IP
	a.Port = int64(tcpAddr.Port)
	a.Zone = tcpAddr.Zone

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

	a.Port = int64(port)
	a.Zone = ""

	return nil
}

// IsRoutable returns true iff the address is likely to be globally routable.
func (a *Address) IsRoutable() bool {
	return common.IsProbablyGloballyReachable(a.IP)
}

// String returns the string representation of an address.
func (a Address) String() string {
	ip := a.IP.String()
	if a.Zone != "" {
		return net.JoinHostPort(ip+"%"+a.Zone, fmt.Sprintf("%d", a.Port))
	}
	return net.JoinHostPort(ip, fmt.Sprintf("%d", a.Port))
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
