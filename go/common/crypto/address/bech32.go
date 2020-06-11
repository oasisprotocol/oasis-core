package address

import (
	"errors"
	"fmt"
	"sync"
)

// Bech32HRPMaxSize is the maximum size of a human readable part (HRP) of Bech32
// encoded addresses.
// NOTE: Although Bech32 HRPs can be up to 83 characters long, the whole Bech32
// string is limited to 90 characters, including data and 6 characters for error
// detection. Hence, it is better to limit HRPs to some smaller number.
const Bech32HRPMaxSize = 15

var (
	// ErrMalformedBech32HRP is the error returned when a Bech32 HRP is malformed.
	ErrMalformedBech32HRP = errors.New("address: malformed Bech32 human readable part")

	registeredBech32HRPs sync.Map
)

// Bech32HRP is the human readable part (HRP) of Bech32 encoded addresses.
type Bech32HRP string

// String returns the string representation of a HRP of Bech32 encoded addresses.
func (hrp Bech32HRP) String() string {
	return string(hrp)
}

// NewBech32HRP creates and registers a new human readable part (HRP) of Bech32
// encoded addresses.
// This routine will panic if the Bech32 HRP is malformed or is already registered.
func NewBech32HRP(rawBech32HRP string) Bech32HRP {
	// NOTE: Bech32 HRPs of length 0 are invalid.
	l := len(rawBech32HRP)
	if l == 0 {
		panic(ErrMalformedBech32HRP)
	}
	if l > Bech32HRPMaxSize {
		panic(ErrMalformedBech32HRP)
	}

	bech32HRP := Bech32HRP(rawBech32HRP)
	if _, loaded := registeredBech32HRPs.LoadOrStore(bech32HRP, true); loaded {
		panic(fmt.Sprintf("address: Bech32 human readable part '%s' is already registered", bech32HRP))
	}

	return bech32HRP
}
