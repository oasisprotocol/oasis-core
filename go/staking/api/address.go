package api

import (
	"encoding"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/address"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/encoding/bech32"
)

var (
	// AddressV0Context is the unique context for v0 staking account addresses.
	AddressV0Context = address.NewContext("oasis-core/address: staking", 0)
	// AddressBech32HRP is the unique human readable part of Bech32 encoded
	// staking account addresses.
	AddressBech32HRP = address.NewBech32HRP("oasis")

	_ encoding.BinaryMarshaler   = Address{}
	_ encoding.BinaryUnmarshaler = (*Address)(nil)
	_ encoding.TextMarshaler     = Address{}
	_ encoding.TextUnmarshaler   = (*Address)(nil)

	reservedAddresses sync.Map
)

// Address is the staking account address.
type Address address.Address

// MarshalBinary encodes an address into binary form.
func (a Address) MarshalBinary() ([]byte, error) {
	return (address.Address)(a).MarshalBinary()
}

// UnMarshalBinary decodes a binary marshaled address.
func (a *Address) UnmarshalBinary(data []byte) error {
	return (*address.Address)(a).UnmarshalBinary(data)
}

// MarshalText encodes an address into text form.
func (a Address) MarshalText() ([]byte, error) {
	return (address.Address)(a).MarshalBech32(AddressBech32HRP)
}

// UnmarshalText decodes a text marshaled address.
func (a *Address) UnmarshalText(text []byte) error {
	return (*address.Address)(a).UnmarshalBech32(AddressBech32HRP, text)
}

// Equal compares vs another address for equality.
func (a Address) Equal(cmp Address) bool {
	return (address.Address)(a).Equal((address.Address)(cmp))
}

// String returns the string representation of an address.
func (a Address) String() string {
	bech32Addr, err := bech32.Encode(AddressBech32HRP.String(), a[:])
	if err != nil {
		return "[malformed]"
	}
	return bech32Addr
}

// Reserve adds the address to the reserved addresses list.
func (a Address) Reserve() error {
	_, loaded := reservedAddresses.LoadOrStore(a, true)
	if loaded {
		return fmt.Errorf("address: address '%s' is already reserved", a)
	}
	return nil
}

// IsReserved returns true iff the address is reserved, prohibited from regular
// use.
func (a Address) IsReserved() bool {
	_, isReserved := reservedAddresses.Load(a)
	return isReserved
}

// IsValid checks whether an address is well-formed and not reserved.
func (a Address) IsValid() bool {
	return address.Address(a).IsValid() && !a.IsReserved()
}

// NewAddress creates a new address from the given public key, i.e. entity ID.
func NewAddress(pk signature.PublicKey) (a Address) {
	pkData, _ := pk.MarshalBinary()
	return (Address)(address.NewAddress(AddressV0Context, pkData))
}

// NewReservedAddress creates a new reserved address from the given public key
// or panics.
// NOTE: The given public key is also blacklisted.
func NewReservedAddress(pk signature.PublicKey) (a Address) {
	// Blacklist the public key.
	if err := pk.Blacklist(); err != nil {
		panic(err)
	}

	// Add the address to the reserved addresses list.
	addr := NewAddress(pk)
	if err := addr.Reserve(); err != nil {
		panic(err)
	}

	return addr
}
