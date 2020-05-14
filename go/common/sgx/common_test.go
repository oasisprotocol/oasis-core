package sgx

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMrSignerDerivation(t *testing.T) {
	require := require.New(t)

	// This could just use FortanixDummyMrSigner, since it's done in
	// the package init()...
	var mrSigner MrSigner
	err := mrSigner.FromPublicKey(fortanixDummyKey.Public().(*rsa.PublicKey))
	require.NoError(err, "Derive MRSIGNER")

	require.Equal(mrSigner.String(), "9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a")
}
