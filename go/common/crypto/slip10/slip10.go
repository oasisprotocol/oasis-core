// Package slip10 implements the SLIP-0010 private key derivation
// scheme for Ed25519.
package slip10

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

const (
	// SeedMinSize is the minimum seed byte sequence size in bytes.
	SeedMinSize = 16

	// SeedMaxSize is the maximum seed byte sequence size in bytes.
	SeedMaxSize = 64

	// ChainCodeSize is the size of a SLIP-0010 chain code in bytes.
	ChainCodeSize = 32
)

var curveConstant = []byte("ed25519 seed")

// ChainCode is a SLIP-0010 chain code.
type ChainCode [ChainCodeSize]byte

// NewMasterKey derives a master key and chain code from a seed byte sequence.
func NewMasterKey(seed []byte) (signature.Signer, ChainCode, error) {
	// Let S be a seed byte sequence of 128 to 512 bits in length.
	if sLen := len(seed); sLen < SeedMinSize || sLen > SeedMaxSize {
		return nil, ChainCode{}, fmt.Errorf("slip10: invalid seed")
	}

	// 1. Calculate I = HMAC-SHA512(Key = Curve, Data = S)
	mac := hmac.New(sha512.New, curveConstant)
	_, _ = mac.Write(seed)
	I := mac.Sum(nil)

	// 2. Split I into two 32-byte sequences, IL and IR.
	// 3. Use parse256(IL) as master secret key, and IR as master chain code.
	return splitDigest(I)
}

// NewChildKey derives a child key and chain code from a (parent key,
// parent chain code, index) tuple.
func NewChildKey(parentSigner signature.Signer, cPar ChainCode, index uint32) (signature.Signer, ChainCode, error) {
	unsafeSigner, ok := parentSigner.(signature.UnsafeSigner)
	if !ok {
		return nil, ChainCode{}, fmt.Errorf("slip10: failed to get parent public key")
	}

	kPar := unsafeSigner.UnsafeBytes() // nolint: revive
	if len(kPar) < memory.SeedSize {
		return nil, ChainCode{}, fmt.Errorf("slip10: invalid parent key")
	}

	// 1. Check whether i >= 2^31 (whether the child is a hardened key).
	if index < 1<<31 {
		// If not (normal child):
		// If curve is ed25519: return failure.
		return nil, ChainCode{}, fmt.Errorf("slip10: non-hardened keys not supported")
	}

	// If so (hardened child):
	// let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
	// (Note: The 0x00 pads the private key to make it 33 bytes long.)
	var b [4]byte
	mac := hmac.New(sha512.New, cPar[:])
	_, _ = mac.Write(b[0:1])                 // 0x00
	_, _ = mac.Write(kPar[:memory.SeedSize]) // ser256(kPar)
	binary.BigEndian.PutUint32(b[:], index)  // Note: The spec neglects to define ser32.
	_, _ = mac.Write(b[:])                   // ser32(i)
	I := mac.Sum(nil)

	// 2. Split I into two 32-byte sequences, IL and IR.
	// 3. The returned chain code ci is IR.
	// 4. If curve is ed25519: The returned child key ki is parse256(IL).
	return splitDigest(I)
}

func splitDigest(digest []byte) (signature.Signer, ChainCode, error) {
	IL, IR := digest[:32], digest[32:]

	var chainCode ChainCode
	signer, err := memory.NewFromSeed(IL)
	if err != nil {
		return nil, chainCode, err
	}
	copy(chainCode[:], IR)

	return signer, chainCode, nil
}
