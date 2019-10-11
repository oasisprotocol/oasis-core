package sgx

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMrSignerDerivation(t *testing.T) {
	require := require.New(t)

	rawPem, err := ioutil.ReadFile("testdata/dummy.pub.pem")
	require.NoError(err, "Load test public key")

	blk, _ := pem.Decode(rawPem)
	require.NotNil(blk, "Test public key PEM has a block")

	nakedPubKey, err := x509.ParsePKIXPublicKey(blk.Bytes)
	require.NoError(err, "Parse PKIX RSA public key")

	rsaPubKey := nakedPubKey.(*rsa.PublicKey)

	var mrSigner MrSigner
	err = mrSigner.FromPublicKey(rsaPubKey)
	require.NoError(err, "Derive MRSIGNER")

	require.Equal(mrSigner.String(), "9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a")
}
