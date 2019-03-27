package sivaessha2

import (
	"crypto/sha512"

	"github.com/oasislabs/ekiden/go/common/crypto/mrae/api"
)

var (
	// Box is the asymmetric ("Box") interface implementation.
	Box = &boxImpl{}

	boxKDFTweak = []byte("MRAE_Box_SIV_CTR-AES128_HMAC-SHA256-128")
)

type boxImpl struct{}

func (impl *boxImpl) DeriveSymmetricKey(key []byte, publicKey, privateKey *[32]byte) {
	api.ECDHAndTweak(key, publicKey, privateKey, sha512.New384, boxKDFTweak)
}

func (impl *boxImpl) Seal(dst, nonce, plaintext, additionalData []byte, peersPublicKey, privateKey *[32]byte) []byte {
	var k [KeySize]byte
	impl.DeriveSymmetricKey(k[:], peersPublicKey, privateKey)

	aead, err := New(k[:])
	api.Bzero(k[:])
	if err != nil {
		panic(err)
	}

	ret := aead.Seal(dst, nonce, plaintext, additionalData)
	aead.(api.ResetAble).Reset()

	return ret
}

func (impl *boxImpl) Open(dst, nonce, plaintext, additionalData []byte, peersPublicKey, privateKey *[32]byte) ([]byte, error) {
	var k [KeySize]byte
	impl.DeriveSymmetricKey(k[:], peersPublicKey, privateKey)

	aead, err := New(k[:])
	api.Bzero(k[:])
	if err != nil {
		panic(err)
	}

	ret, err := aead.Open(dst, nonce, plaintext, additionalData)
	aead.(api.ResetAble).Reset()

	return ret, err
}
