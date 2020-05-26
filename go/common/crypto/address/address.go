// Package address implements a generic cryptographic address with versioning
// and context separation. It can be used to implement specific addresses, e.g.
// the staking account address.
package address

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/encoding/bech32"
)

const (
	// VersionSize is the size of address' version.
	VersionSize = 1
	// Size is the size of the whole address where the last 20 bytes represent
	// truncated hash of the concatenation of address' context and data.
	Size = VersionSize + 20
)

var (
	// ErrMalformed is the error returned when an address is malformed.
	ErrMalformed = errors.New("address: malformed address")

	_ encoding.BinaryMarshaler   = Address{}
	_ encoding.BinaryUnmarshaler = (*Address)(nil)
)

// Address is a versioned context-separated truncated hash of the raw address data.
type Address [Size]byte

// MarshalBinary encodes an address into binary form.
func (a Address) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, a[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled address.
func (a *Address) UnmarshalBinary(data []byte) error {
	if len(data) != Size {
		return ErrMalformed
	}

	copy(a[:], data)

	return nil
}

// MarshalBech32 encodes an address into Bech32-encoded text form.
func (a Address) MarshalBech32(hrp Bech32HRP) ([]byte, error) {
	if _, isRegistered := registeredBech32HRPs.Load(hrp); !isRegistered {
		panic(fmt.Sprintf("address: Bech32 human readable part '%s' is not registered", hrp))
	}
	bech32Addr, err := bech32.Encode(hrp.String(), a[:])
	if err != nil {
		return nil, fmt.Errorf("address: encoding to bech32 failed: %w", err)
	}
	return []byte(bech32Addr), nil
}

// UnmarshalBech32 decodes a Bech32-encoded text marshaled address.
func (a *Address) UnmarshalBech32(hrp Bech32HRP, bech []byte) error {
	if _, isRegistered := registeredBech32HRPs.Load(hrp); !isRegistered {
		panic(fmt.Sprintf("address: Bech32 human readable part '%s' is not registered", hrp))
	}
	decodedHrp, decoded, err := bech32.Decode(string(bech))
	if err != nil {
		return fmt.Errorf("address: decoding from bech32 failed: %w", err)
	}
	if decodedHrp != hrp.String() {
		return fmt.Errorf("address: incorrect bech32 human readable part: %s (expected: %s)",
			decodedHrp, hrp,
		)
	}

	return a.UnmarshalBinary(decoded)
}

// Equal compares vs another address for equality.
func (a Address) Equal(cmp Address) bool {
	return bytes.Equal(a[:], cmp[:])
}

// IsValid checks whether an address is well-formed.
func (a Address) IsValid() bool {
	return len(a) == Size
}

// NewAddress creates a new address of specified version from address' context and data.
func NewAddress(ctx Context, data []byte) (a Address) {
	if _, isRegistered := registeredContexts.Load(ctx); !isRegistered {
		panic(fmt.Sprintf("address: context %s is not registered", ctx))
	}

	ctxData, _ := ctx.MarshalBinary()
	h := hash.NewFromBytes(ctxData, data)
	truncatedHash, err := h.Truncate(Size - VersionSize)
	if err != nil {
		panic(err)
	}
	_ = a.UnmarshalBinary(append([]byte{ctx.Version}, truncatedHash...))
	return
}
