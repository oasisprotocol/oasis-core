package sgx

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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

func TestSerializationYAML(t *testing.T) {
	require := require.New(t)

	const testCase1 = `"pKgjl8iaPXez72EYTefLI+fIOR5dyoLW9aCdDCyY15qoN79uRyzpbZpzSyXQIkXu+qm+r7/VJPY+Im3P4riXDg=="`
	var dec EnclaveIdentity
	err := yaml.Unmarshal([]byte(testCase1), &dec)
	require.NoError(err, "yaml.Unmarshal")
	require.EqualValues("a837bf6e472ce96d9a734b25d02245eefaa9beafbfd524f63e226dcfe2b8970e", dec.MrSigner.String())
	require.EqualValues("a4a82397c89a3d77b3ef61184de7cb23e7c8391e5dca82d6f5a09d0c2c98d79a", dec.MrEnclave.String())
}
