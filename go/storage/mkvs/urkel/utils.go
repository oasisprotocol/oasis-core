package urkel

import "github.com/oasislabs/ekiden/go/common/crypto/hash"

func hashKey(key []byte) (h hash.Hash) {
	h.FromBytes(key)
	return
}

func getKeyBit(key hash.Hash, bit uint8) bool {
	return key[bit/8]&(1<<(7-(bit%8))) != 0
}

func setKeyBit(key hash.Hash, bit uint8, val bool) hash.Hash {
	var h hash.Hash
	copy(h[:], key[:])

	mask := byte(1 << (7 - (bit % 8)))
	if val {
		h[bit/8] |= mask
	} else {
		h[bit/8] &= mask
	}
	return h
}
