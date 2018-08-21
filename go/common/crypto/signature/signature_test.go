package signature

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrivateKey(t *testing.T) {
	t.Run("Generation", testPrivateKeyCtor)
	t.Run("Serialization", testPrivateKeyS11n)
	t.Run("Disk", testPrivateKeyDisk)
}

func testPrivateKeyCtor(t *testing.T) {
	var zeroPrivKey PrivateKey
	var zeroPubKey PublicKey

	pk, err := NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey()")
	require.NotEqual(t, zeroPrivKey, pk, "PrivateKey is random")
	require.NotEqual(t, zeroPubKey, pk.Public(), "PublicKey is sensible")
}

func testPrivateKeyS11n(t *testing.T) {
	pk, err := NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey()")

	pem, err := pk.MarshalPEM()
	require.NoError(t, err, "MarshalPEM()")

	var pk2 PrivateKey
	err = pk2.UnmarshalPEM(pem)
	require.NoError(t, err, "UnmarshalPEM()")
	require.Equal(t, pk, pk2, "PEM round trip")
}

func testPrivateKeyDisk(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "ekiden-signature-test")
	require.NoError(t, err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	fn := filepath.Join(tmpDir, "private.pem")
	var k PrivateKey

	// Missing, no generate.
	err = k.LoadPEM(fn, nil)
	require.Error(t, err, "LoadPEM(fn, nil), missing")

	// Missing, generate.
	err = k.LoadPEM(fn, rand.Reader)
	require.NoError(t, err, "LoadPEM(fn, rand.Reader)")

	// Exists.
	var kk PrivateKey
	err = kk.LoadPEM(fn, nil)
	require.NoError(t, err, "LoadPEM(fn, nil), exists")
	require.Equal(t, k, kk, "Generated = Loaded")
}
