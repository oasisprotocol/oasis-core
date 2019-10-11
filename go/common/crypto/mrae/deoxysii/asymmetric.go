// Package deoxysii implements the Deoxys-II-256-128 based MRAE boxes.
package deoxysii

import (
	"crypto/sha256"

	"github.com/oasislabs/deoxysii"
	"github.com/oasislabs/oasis-core/go/common/crypto/mrae/api"
)

var (
	// Box is the asymmetric "Box" interface implementation.
	Box = &boxImpl{}

	boxKDFTweak = []byte("MRAE_Box_Deoxys-II-256-128")
)

type boxImpl struct{}

func (impl *boxImpl) DeriveSymmetricKey(key []byte, publicKey, privateKey *[32]byte) {
	api.ECDHAndTweak(key, publicKey, privateKey, sha256.New, boxKDFTweak)
}

func (impl *boxImpl) Seal(dst, nonce, plaintext, additionalData []byte, peersPublicKey, privateKey *[32]byte) []byte {
	var k [deoxysii.KeySize]byte
	impl.DeriveSymmetricKey(k[:], peersPublicKey, privateKey)

	aead, err := deoxysii.New(k[:])
	api.Bzero(k[:])
	if err != nil {
		panic(err)
	}

	ret := aead.Seal(dst, nonce, plaintext, additionalData)
	aead.(api.ResetAble).Reset()

	return ret
}

func (impl *boxImpl) Open(dst, nonce, plaintext, additionalData []byte, peersPublicKey, privateKey *[32]byte) ([]byte, error) {
	var k [deoxysii.KeySize]byte
	impl.DeriveSymmetricKey(k[:], peersPublicKey, privateKey)

	aead, err := deoxysii.New(k[:])
	api.Bzero(k[:])
	if err != nil {
		panic(err)
	}

	ret, err := aead.Open(dst, nonce, plaintext, additionalData)
	aead.(api.ResetAble).Reset()

	return ret, err
}
