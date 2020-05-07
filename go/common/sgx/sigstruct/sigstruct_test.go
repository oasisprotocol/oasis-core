package sigstruct

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
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
		WithBuildDate(time.Date(2016, 01, 9, 0, 0, 0, 0, time.UTC)),
		WithAttributes(ias.Attributes{
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
}

func loadTestPrivateKey() (*rsa.PrivateKey, error) {
	rawPEM, err := ioutil.ReadFile("../testdata/sig1.key.pem")
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(rawPEM)
	return x509.ParsePKCS1PrivateKey(blk.Bytes)
}
