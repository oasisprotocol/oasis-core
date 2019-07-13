package file

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

func TestFileSigner(t *testing.T) {
	require := require.New(t)

	var zeroSigner Signer
	var zeroPubKey signature.PublicKey

	tmpDir, err := ioutil.TempDir("", "ekiden-signature-test")
	require.NoError(err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	fn := filepath.Join(tmpDir, "private.pem")

	factory := NewFactory(signature.SignerUnknown)

	// Missing, no generate.
	_, err = factory.Load(fn)
	require.Error(err, "Load(fn), missing")

	// Generate.
	var signer signature.Signer
	signer, err = factory.Generate(fn, rand.Reader)
	require.NoError(err, "Generate(fn, rand.Reader)")
	require.NotEqual(zeroSigner, signer, "PrivateKey is random")
	require.NotEqual(zeroPubKey, signer.Public(), "PublicKey is sensible")

	// PEM round trips.
	actualSigner := signer.(*Signer)
	pem, err := actualSigner.marshalPEM()
	require.NoError(err, "marshalPEM()")

	var actualSigner2 Signer
	err = actualSigner2.unmarshalPEM(pem)
	require.NoError(err, "UnmarshalPEM()")
	require.Equal(actualSigner, &actualSigner2, "PEM round trip")

	// Exists.
	signer2, err := factory.Load(fn)
	require.NoError(err, "LoadPEM(fn, nil), exists")
	require.Equal(signer, signer2, "Generated = Loaded")
}
