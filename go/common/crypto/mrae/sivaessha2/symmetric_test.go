package sivaessha2

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/oasislabs/ekiden/go/common/crypto/mrae/gen_vectors/testvector"

	"github.com/stretchr/testify/require"
)

func TestSIV_AES_SHA2_Integration(t *testing.T) {
	var k [KeySize]byte
	var n [NonceSize]byte
	var aad [13]byte
	var msg [64]byte

	for i := range k {
		k[i] = byte(i)
	}
	for i := range n {
		n[i] = byte(i + KeySize)
	}
	for i := range aad {
		aad[i] = byte(i + KeySize + NonceSize)
	}
	for i := range msg {
		msg[i] = byte(i + KeySize + NonceSize + len(aad))
	}

	// Test creating an AEAD instance.
	aead, err := New(k[:])
	require.NoError(t, err, "New")

	// Test that Seal appears to work.
	ct := aead.Seal(nil, n[:], msg[:], aad[:])
	require.Len(t, ct, len(msg)+TagSize, "Seal")

	// Test that Open appears to work.
	pt, err := aead.Open(nil, n[:], ct, aad[:])
	require.NoError(t, err, "Open")
	require.EqualValues(t, msg[:], pt, "Open expected ?= plaintext")

	// Test that Open fails with a invalid AAD.
	badAad := append([]byte{}, aad[:]...)
	badAad[0] ^= 0xa5
	pt, err = aead.Open(nil, n[:], ct, badAad)
	require.Nil(t, pt, "Open (Malformed AAD, plaintext)")
	require.Error(t, err, "Open (Malformed AAD)")

	// Test that Open fails with a invalid ciphertext.
	badCt := append([]byte{}, ct[:]...)
	badCt[23] ^= 0xa5
	pt, err = aead.Open(nil, n[:], badCt, aad[:])
	require.Nil(t, pt, "Open (Malformed C, plaintext)")
	require.Error(t, err, "Open (Malformed C)")

	// Test that Open fails with a truncated ciphertext.
	pt, err = aead.Open(nil, n[:], ct[:5], aad[:])
	require.Nil(t, pt, "Open (Truncated C, plaintext)")
	require.Error(t, err, "Open (Truncated C)")
}

func TestSIV_AES_SHA2_KAT(t *testing.T) {
	a := require.New(t)
	fn := filepath.Join("testdata", "SIV_CTR-AES128_HMAC-SHA256-128.json")
	testvector.ValidateKATs(a, fn, New)
}

func BenchmarkSIV_AES_SHA2(b *testing.B) {
	benchSizes := []int{8, 32, 64, 576, 1536, 4096, 1024768}

	for _, sz := range benchSizes {
		bn := "SIV_CTR-AES128_HMAC-SHA256-128" + "_"
		sn := fmt.Sprintf("_%d", sz)
		b.Run(bn+"Encrypt"+sn, func(b *testing.B) { doBenchmarkAEADSeal(b, sz) })
		b.Run(bn+"Decrypt"+sn, func(b *testing.B) { doBenchmarkAEADOpen(b, sz) })
	}
}

func doBenchmarkAEADSeal(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, NonceSize), make([]byte, KeySize)
	m, c := make([]byte, sz), make([]byte, 0, sz+TagSize)
	rand.Read(nonce)
	rand.Read(key)
	rand.Read(m)

	aead, _ := New(key)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c = aead.Seal(c[:0], nonce, m, nil)
		if len(c) != sz+TagSize {
			b.Fatalf("aead.Seal failed")
		}
	}
}

func doBenchmarkAEADOpen(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, NonceSize), make([]byte, KeySize)
	m, c, d := make([]byte, sz), make([]byte, 0, sz+TagSize), make([]byte, 0, sz)
	rand.Read(nonce)
	rand.Read(key)
	rand.Read(m)

	aead, _ := New(key)

	c = aead.Seal(c, nonce, m, nil)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		d = d[:0]

		var err error
		d, err = aead.Open(d[:0], nonce, c, nil)
		if err != nil {
			b.Fatalf("aead.Open failed: %v", err)
		}
	}
	b.StopTimer()

	if !bytes.Equal(m, d) {
		b.Fatalf("aeadDecrypt output mismatch")
	}
}
