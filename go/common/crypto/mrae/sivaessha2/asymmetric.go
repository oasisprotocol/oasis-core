package sivaessha2

import (
	"crypto/hmac"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/curve25519"
)

var boxKDFTweak = []byte("MRAE_Box_SIV_CTR-AES128_HMAC-SHA256-128")

// BoxSeal boxes ("seals") the provided additional data and plaintext
// via SIV_CTR-AES128_HMAC-SHA256-128 using a symmetric key derived
// from the provided X25519 public and private keys, appending the
// result to dst, returning the updated slice.  The nonce SHOULD be
// NonceSize bytes long and unique for all time, for a given public
// and private key tuple.
//
// The plaintext and dst must overlap exactly or not at all.  To reuse
// plaintext's storage for encrypted output, use plaintext[:0] as dst.
func BoxSeal(dst, nonce, plaintext, additionalData []byte, peersPublicKey, privateKey *[32]byte) []byte {
	var k [KeySize]byte
	DeriveSymmetricKey(&k, peersPublicKey, privateKey)

	aead, err := New(k[:])
	if err != nil {
		panic(err)
	}

	ret := aead.Seal(dst, nonce, plaintext, additionalData)
	aead.(*sivImpl).reset() // Not using defer to save a heap alloc.

	return ret
}

// BoxOpen unboxes ("opens") the provided additonal data and ciphertext
// via SIV_CTR-AES128_HMAC-SHA256-128 using a symmetric key dervied
// from the provided X25519 public and private keys and, if successful,
// appends the resulting plaintext to dst, returning the updated slice.
// The nonce SHOULD be NonceSize bytes long and both it and the additional
// data must match the value passed to Seal.
//
// The ciphertext and dst must overlap exactly or not at all.  To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
//
// Even if the function fails, the contents of dst, up to it's capacity,
// may be overwritten.
func BoxOpen(dst, nonce, plaintext, additionalData []byte, peersPublicKey, privateKey *[32]byte) ([]byte, error) {
	var k [KeySize]byte
	DeriveSymmetricKey(&k, peersPublicKey, privateKey)

	aead, err := New(k[:])
	if err != nil {
		panic(err)
	}

	ret, err := aead.Open(dst, nonce, plaintext, additionalData)
	aead.(*sivImpl).reset() // Not using defer to save a heap alloc.

	return ret, err
}

// DeriveSymmetricKey derives a MRAE AEAD symmetric key suitable for use with
// the Box API from the provided X25519 public and private keys.
func DeriveSymmetricKey(key *[KeySize]byte, publicKey, privateKey *[32]byte) {
	var pmk [32]byte
	curve25519.ScalarMult(&pmk, privateKey, publicKey)

	kdf := hmac.New(sha512.New384, boxKDFTweak)
	_, _ = kdf.Write(pmk[:])
	bzero(pmk[:])
	tmp := kdf.Sum(nil)

	copy(key[:], tmp)
	bzero(tmp)
}

// GenerateKeyPair generates a public/private key pair suitable for use
// with DeriveSymmetricKey, BoxSeal, and BoxOpen.
func GenerateKeyPair(rng io.Reader) (publicKey, privateKey *[32]byte, err error) {
	var entropy [32]byte
	if _, err = io.ReadFull(rng, entropy[:]); err != nil {
		return
	}

	tmp := sha512.Sum512_256(entropy[:]) // Mitigate poor quality entropy.
	bzero(entropy[:])
	privateKey = &tmp
	publicKey = new([32]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)

	return
}
