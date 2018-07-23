// Package ethereum provides types and routines for interacting with
// Ethereum.
package ethereum

import (
	"encoding"
	"errors"
)

var (
	// ErrInvalidAddress is the error returned when an address is invalid.
	ErrInvalidAddress = errors.New("ethereum: invalid address")

	_ encoding.BinaryMarshaler   = (*Address)(nil)
	_ encoding.BinaryUnmarshaler = (*Address)(nil)
)

// AddressSize is the length of an Ethereum address in bytes.
const AddressSize = 20

// Address is an Ethereum address.
type Address [20]byte

// MarshalBinary encodes a Ethereum Address into binary form.
func (a *Address) MarshalBinary() (data []byte, err error) {
	data = make([]byte, AddressSize)
	copy(data, a[:])

	return
}

// UnmarshalBinary decodes a binary marshaled Ethereum address.
func (a *Address) UnmarshalBinary(data []byte) error {
	if len(data) != AddressSize {
		return ErrInvalidAddress
	}

	copy(a[:], data)

	return nil
}
