package identity

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadOrGenerate(t *testing.T) {
	dataDir, err := ioutil.TempDir("", "ekiden-identity-test_")
	require.NoError(t, err, "create data dir")
	defer os.RemoveAll(dataDir)

	// Generate a new identity.
	identity, err := LoadOrGenerate(dataDir)
	require.NoError(t, err, "LoadOrGenerate")

	// Load an existing identity.
	identity2, err := LoadOrGenerate(dataDir)
	require.NoError(t, err, "LoadOrGenerate")
	require.EqualValues(t, identity.NodeKey, identity2.NodeKey)
	require.EqualValues(t, identity.TLSKey, identity2.TLSKey)
	// TODO: Check that it always generates a fresh certificate once ekiden#1541 is done.
	require.EqualValues(t, identity.TLSCertificate, identity2.TLSCertificate)
}
