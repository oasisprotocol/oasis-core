package sivaessha2

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

func TestSIV_AES_SHA2_Box_GenerateKeypair(t *testing.T) {
	pub, priv, err := GenerateKeyPair(rand.Reader)
	require.NoError(t, err, "GenerateKeyPair")

	var pubTmp [32]byte
	curve25519.ScalarBaseMult(&pubTmp, priv)
	require.EqualValues(t, pub, &pubTmp, "scalarBaseMult(priv) ?= pub")
}

func TestSIV_AES_SHA2_Box_Integration(t *testing.T) {
	alicePub, alicePriv, err := GenerateKeyPair(rand.Reader)
	require.NoError(t, err, "GenerateKeyPair(Alice)")

	bobPub, bobPriv, err := GenerateKeyPair(rand.Reader)
	require.NoError(t, err, "GenerateKeyPair(Bob)")

	var n [NonceSize]byte
	var aad [23]byte
	var msg [96]byte

	for i := range n {
		n[i] = byte(i)
	}
	for i := range aad {
		aad[i] = byte(i + NonceSize)
	}
	for i := range msg {
		msg[i] = byte(i + NonceSize + len(aad))
	}

	// Alice: Box
	ct := BoxSeal(nil, n[:], msg[:], aad[:], bobPub, alicePriv)

	// Ensure that BoxSeal is equvialent to Derive + AEAD.Seal.
	var k [KeySize]byte
	DeriveSymmetricKey(&k, bobPub, alicePriv)
	aead, err := New(k[:])
	require.NoError(t, err, "DeriveSymmetricKey")
	ctCmp := aead.Seal(nil, n[:], msg[:], aad[:])
	require.EqualValues(t, ctCmp, ct, "BoxSeal ?= Derive + AEAD.Seal")

	// Bob: Unbox
	pt, err := BoxOpen(nil, n[:], ct, aad[:], alicePub, bobPriv)
	require.NoError(t, err, "BoxOpen")
	require.EqualValues(t, msg[:], pt, "BoxOpen expected ?= plaintext")
}
