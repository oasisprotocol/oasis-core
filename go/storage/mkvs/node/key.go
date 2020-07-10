package node

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
)

// Key holds variable-length key.
type Key []byte

// String returns a string representation of the key.
func (k Key) String() string {
	return hex.EncodeToString(k[:])
}

// MarshalBinary encodes a key length in bytes + key into binary form.
func (k Key) MarshalBinary() (data []byte, err error) {
	data = make([]byte, DepthSize+len(k))
	binary.LittleEndian.PutUint16(data[0:DepthSize], uint16(len(k)))
	if k != nil {
		copy(data[DepthSize:], k[:])
	}
	return
}

// UnmarshalBinary decodes a binary marshaled key including the length in bytes.
func (k *Key) UnmarshalBinary(data []byte) error {
	_, err := k.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled key incl. length in bytes.
func (k *Key) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < DepthSize {
		return 0, ErrMalformedKey
	}

	keyLen := binary.LittleEndian.Uint16(data[0:DepthSize])
	if len(data) < DepthSize+int(keyLen) {
		return 1, ErrMalformedKey
	}

	if keyLen > 0 {
		*k = make([]byte, keyLen)
		copy(*k, data[DepthSize:DepthSize+int(keyLen)])
	} else if k != nil {
		// If the key we are unmarshaling into is not nil, make sure that
		// it is at least of size zero.
		*k = []byte{}
	}
	return DepthSize + int(keyLen), nil
}

// Equal compares the key with some other key.
func (k Key) Equal(other Key) bool {
	if k != nil {
		return bytes.Equal(k, other)
	}
	return other == nil
}

// Compare compares the key with some other key and returns 0 if both
// keys are equal, -1 if the the key is smaller and 1 if the key is
// larger.
func (k Key) Compare(other Key) int {
	return bytes.Compare(k, other)
}

// ToMapKey returns the key in a form to be used as a Go's map key.
func ToMapKey(k []byte) string {
	return string(k)
}

// BitLength returns the length of the key in bits.
func (k Key) BitLength() Depth {
	return Depth(len(k[:]) * 8)
}

// GetKeyBit returns the given bit of the key.
func (k Key) GetBit(bit Depth) bool {
	return k[bit/8]&(1<<(7-(bit%8))) != 0
}

// SetKeyBit sets the bit at the given position bit to value val.
//
// This function is immutable and returns a new instance of Key
func (k Key) SetBit(bit Depth, val bool) Key {
	kb := make(Key, len(k))
	copy(kb[:], k[:])
	mask := byte(1 << (7 - (bit % 8)))
	if val {
		kb[bit/8] |= mask
	} else {
		kb[bit/8] &= mask
	}
	return kb
}

// Split performs bit-wise split of the key.
//
// keyLen is the length of the key in bits and splitPoint is the index of the
// first suffix bit.
// This function is immutable and returns two new instances of Key.
func (k Key) Split(splitPoint, keyLen Depth) (prefix, suffix Key) {
	if splitPoint > keyLen {
		panic(fmt.Sprintf("mkvs: splitPoint %+v greater than keyLen %+v", splitPoint, keyLen))
	}
	prefixLen := Depth(splitPoint.ToBytes())
	suffixLen := Depth((keyLen - splitPoint).ToBytes())
	prefix = make(Key, prefixLen)
	suffix = make(Key, suffixLen)

	copy(prefix[:], k[:])
	// Clean the remainder of the byte.
	if splitPoint%8 != 0 {
		prefix[prefixLen-1] &= 0xff << (8 - splitPoint%8)
	}

	for i := Depth(0); i < suffixLen; i++ {
		// First set the left chunk of the byte
		suffix[i] = k[i+splitPoint/8] << (splitPoint % 8)
		// ...and the right chunk, if we haven't reached the end of k yet.
		if splitPoint%8 != 0 && i+splitPoint/8+1 != Depth(len(k)) {
			suffix[i] |= k[i+splitPoint/8+1] >> (8 - splitPoint%8)
		}
	}

	return
}

// Merge bit-wise merges key of given length with another key of given length.
//
// keyLen is the length of the original key in bits and k2Len is the length of
// another key in bits.
// This function is immutable and returns a new instance of Key.
func (k Key) Merge(keyLen Depth, k2 Key, k2Len Depth) Key {
	keyLenBytes := int(keyLen) / 8
	if keyLen%8 != 0 {
		keyLenBytes++
	}

	newKey := make(Key, (keyLen + k2Len).ToBytes())
	copy(newKey[:], k[:keyLenBytes])

	for i := 0; i < len(k2); i++ {
		// First set the right chunk of the previous byte
		if keyLen%8 != 0 && keyLenBytes > 0 {
			newKey[keyLenBytes+i-1] |= k2[i] >> (keyLen % 8)
		}
		// ...and the next left chunk, if we haven't reached the end of newKey
		// yet.
		if keyLenBytes+i < len(newKey) {
			// another mod 8 to prevent bit shifting for 8 bits
			newKey[keyLenBytes+i] |= k2[i] << ((8 - keyLen%8) % 8)
		}
	}

	return newKey
}

// AppendBit appends the given bit to the key.
//
// This function is immutable and returns a new instance of Key.
func (k Key) AppendBit(keyLen Depth, val bool) Key {
	newKey := make(Key, (keyLen + 1).ToBytes())
	copy(newKey[:len(k)], k[:])

	if val {
		newKey[keyLen/8] |= 0x80 >> (keyLen % 8)
	} else {
		newKey[keyLen/8] &^= 0x80 >> (keyLen % 8)
	}

	return newKey
}

// CommonPrefix computes length of common prefix of k and k2.
//
// Additionally, keyBitLen and k2bitLen are key lengths in bits of k and k2
// respectively.
func (k Key) CommonPrefixLen(keyBitLen Depth, k2 Key, k2bitLen Depth) (bitLength Depth) {
	minKeyLen := len(k)
	if len(k2) < len(k) {
		minKeyLen = len(k2)
	}

	// Compute the common prefix byte-wise.
	i := Depth(0)
	for ; i < Depth(minKeyLen) && k[i] == k2[i]; i++ {
	}

	// Prefixes match i bytes and maybe some more bits below.
	bitLength = i * 8

	if i != Depth(len(k)) && i != Depth(len(k2)) {
		// We got a mismatch somewhere along the way. We need to compute how
		// many additional bits in i-th byte match.
		bitLength += Depth(bits.LeadingZeros8(k[i] ^ k2[i]))
	}

	// In any case, bitLength should never exceed length of the shorter key.
	if bitLength > keyBitLen {
		bitLength = keyBitLen
	}
	if bitLength > k2bitLen {
		bitLength = k2bitLen
	}

	return
}
