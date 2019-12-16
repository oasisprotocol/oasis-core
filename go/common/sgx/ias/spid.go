package ias

import (
	"encoding"
	"encoding/hex"
	"errors"
)

var (
	// ErrMalformedSPID is the error returned when an SPID is malformed.
	ErrMalformedSPID = errors.New("ias: malformed SPID")

	_ encoding.BinaryMarshaler   = (*SPID)(nil)
	_ encoding.BinaryUnmarshaler = (*SPID)(nil)
)

// SPIDSize is the size of SPID.
const SPIDSize = 16

// SPID is an SPID.
type SPID [SPIDSize]byte

// String returns a string representation of the SPID.
func (s SPID) String() string {
	return hex.EncodeToString(s[:])
}

// MarshalBinary encodes an SPID into binary form.
func (s SPID) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, s[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled SPID.
func (s *SPID) UnmarshalBinary(data []byte) error {
	if len(data) != SPIDSize {
		return ErrMalformedSPID
	}

	copy((*s)[:], data)

	return nil
}
