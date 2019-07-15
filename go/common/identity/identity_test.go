package identity

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
)

func TestLoadOrGenerate(t *testing.T) {
	dataDir, err := ioutil.TempDir("", "ekiden-identity-test_")
	require.NoError(t, err, "create data dir")
	defer os.RemoveAll(dataDir)

	factory := fileSigner.NewFactory(dataDir, signature.SignerNode)

	// Generate a new identity.
	identity, err := LoadOrGenerate(dataDir, factory)
	require.NoError(t, err, "LoadOrGenerate")

	// Load an existing identity.
	identity2, err := LoadOrGenerate(dataDir, factory)
	require.NoError(t, err, "LoadOrGenerate")
	require.EqualValues(t, identity.NodeSigner, identity2.NodeSigner)
	require.EqualValues(t, identity.TLSKey, identity2.TLSKey)
	// TODO: Check that it always generates a fresh certificate once ekiden#1541 is done.
	require.EqualValues(t, identity.TLSCertificate, identity2.TLSCertificate)
}
