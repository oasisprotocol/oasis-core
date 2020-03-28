package node

import (
	"encoding/binary"
	"unsafe"
)

// Depth determines the maximum length of the key in bits.
//
// maxKeyLengthInBits = 2^size_of(Depth)*8
type Depth uint16

// DepthSize is the size of Depth in bytes.
const DepthSize = int(unsafe.Sizeof(Depth(0)))

// ToBytes returns the number of bytes needed to fit given bits.
func (dt Depth) ToBytes() int {
	size := dt / 8
	if dt%8 != 0 {
		size++
	}
	return int(size)
}

// MarshalBinary encodes a Depth into binary form.
func (dt Depth) MarshalBinary() []byte {
	data := make([]byte, DepthSize)
	binary.LittleEndian.PutUint16(data, uint16(dt))
	return data
}

// MarshalBinary encodes a Depth into binary form.
func (dt *Depth) UnmarshalBinary(data []byte) (int, error) {
	*dt = Depth(binary.LittleEndian.Uint16(data[0:DepthSize]))
	return DepthSize, nil
}
