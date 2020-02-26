package identity

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
)

func TestLoadOrGenerate(t *testing.T) {
	dataDir, err := ioutil.TempDir("", "oasis-identity-test_")
	require.NoError(t, err, "create data dir")
	defer os.RemoveAll(dataDir)

	factory, err := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	require.NoError(t, err, "NewFactory")

	// Generate a new identity.
	identity, err := LoadOrGenerate(dataDir, factory)
	require.NoError(t, err, "LoadOrGenerate")

	// Load an existing identity.
	identity2, err := LoadOrGenerate(dataDir, factory)
	require.NoError(t, err, "LoadOrGenerate (2)")
	require.EqualValues(t, identity.NodeSigner, identity2.NodeSigner)
	require.EqualValues(t, identity.P2PSigner, identity2.P2PSigner)
	require.EqualValues(t, identity.ConsensusSigner, identity2.ConsensusSigner)
	require.EqualValues(t, identity.TLSSigner, identity2.TLSSigner)
	// TODO: Check that it always generates a fresh certificate once oasis-core#1541 is done.
	require.EqualValues(t, identity.TLSCertificate, identity2.TLSCertificate)
}
