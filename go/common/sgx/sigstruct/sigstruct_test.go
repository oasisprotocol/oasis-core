package sigstruct

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

func TestSigstruct(t *testing.T) {
	require := require.New(t)

	var mrEnclave sgx.MrEnclave
	err := mrEnclave.UnmarshalHex("c50673624a6cb17c1c6c2a4e6906f47a170c4629b8723781d1017ef376f1a75d")
	require.NoError(err, "MrEnclave.UnmarshalHex")

	privateKey, err := loadTestPrivateKey()
	require.NoError(err, "x509.ParsePKCS1PrivateKey")

	// Generate a SIGSTRUCT.
	builder := New(
		WithBuildDate(time.Date(2016, 1, 9, 0, 0, 0, 0, time.UTC)),
		WithAttributes(sgx.Attributes{
			Flags: 0x04,
			Xfrm:  0x03,
		}),
		WithMiscSelectMask(^uint32(0)),
		WithAttributesMask([2]uint64{^uint64(0x2), ^uint64(0xe4)}),
		WithEnclaveHash(mrEnclave),
	)
	sigstruct, err := builder.Sign(privateKey)
	require.NoError(err, "Sigstruct.New")

	expected, err := ioutil.ReadFile("../testdata/sig1.sigstruct.bin")
	require.NoError(err, "ioutil.ReadFile(sig1.sigstruct.bin)")
	require.Equal(expected, sigstruct, "SIGSTRUCT should match Fortanix's")

	extractedPublicKey, derivedBuilder, err := Verify(sigstruct)
	require.NoError(err, "SIGSTRUCT should validate")
	require.EqualValues(builder, derivedBuilder, "Parsed SIGSTRUCT should match builder")
	require.EqualValues(privateKey.Public(), extractedPublicKey, "SIGSTRUCT public key extraction")

	// Test "offline" signing.
	sigHash := builder.HashForSignature()
	expectedSigHash, _ := hex.DecodeString("ea7ced3b8c78324bce65ad851152a125fd1989df324dc72b244ed5f44573ac95")
	require.EqualValues(expectedSigHash, sigHash, "HashForSignature")

	rawSig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sigHash)
	require.NoError(err, "rsa.SignPKCS1v15")

	sigstruct2, err := builder.WithSignature(rawSig, privateKey.Public().(*rsa.PublicKey))
	require.NoError(err, "WithSignature")
	require.EqualValues(sigstruct, sigstruct2, "SIGSTRUCT signed in detached mode should match")
}

func loadTestPrivateKey() (*rsa.PrivateKey, error) {
	rawPEM, err := ioutil.ReadFile("../testdata/sig1.key.pem")
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(rawPEM)
	return x509.ParsePKCS1PrivateKey(blk.Bytes)
}
