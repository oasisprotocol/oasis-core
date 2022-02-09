package file

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

func TestFileSigner(t *testing.T) {
	require := require.New(t)

	var zeroSigner Signer
	var zeroPubKey signature.PublicKey

	tmpDir, err := ioutil.TempDir("", "oasis-signature-test")
	require.NoError(err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	rolePEMFiles[signature.SignerUnknown] = "unit_test.pem"
	factory, err := NewFactory(tmpDir, signature.SignerUnknown)
	require.NoError(err, "NewFactory()")

	// Missing, no generate.
	_, err = factory.Load(signature.SignerUnknown)
	require.Error(err, "Load(fn), missing")

	// Generate.
	var signer signature.Signer
	signer, err = factory.Generate(signature.SignerUnknown, rand.Reader)
	require.NoError(err, "Generate(SignerUnknown, rand.Reader)")
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
	signer2, err := factory.Load(signature.SignerUnknown)
	require.NoError(err, "LoadPEM(fn, nil), exists")
	require.Equal(signer, signer2, "Generated = Loaded")
}

func TestStaticEntropy(t *testing.T) {
	require := require.New(t)

	var zeroSigner Signer
	var zeroEntropy [StaticEntropySize]byte

	tmpDir, err := ioutil.TempDir("", "oasis-signature-test")
	require.NoError(err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	factory, err := NewFactory(tmpDir, signature.SignerP2P)
	require.NoError(err, "NewFactory()")

	// Generate.
	var signer signature.Signer
	signer, err = factory.Generate(signature.SignerP2P, rand.Reader)
	require.NoError(err, "Generate(SignerP2P, rand.Reader)")
	require.NotEqual(zeroSigner, signer, "PrivateKey is random")
	se, err := signer.(signature.StaticEntropyProvider).StaticEntropy()
	require.NoError(err, "StaticEntropy()")
	require.NotEqual(se, zeroEntropy[:], "static entropy is random")

	// Static entropy PEM round trips.
	actualSigner := signer.(*Signer)
	pem, err := actualSigner.marshalStaticEntropyPEM()
	require.NoError(err, "marshalStaticEntropyPEM()")

	var actualSigner2 Signer
	err = actualSigner2.unmarshalStaticEntropyPEM(pem)
	require.NoError(err, "unmarshalStaticEntropyPEM()")
	require.Equal(actualSigner.staticEntropy, actualSigner2.staticEntropy, "static entropy PEM round trip")

	// Exists.
	signer2, err := factory.Load(signature.SignerP2P)
	require.NoError(err, "LoadPEM(fn, nil), exists")
	require.Equal(signer, signer2, "Generated = Loaded")
	se2, err := signer2.(signature.StaticEntropyProvider).StaticEntropy()
	require.NoError(err, "StaticEntropy()")
	require.EqualValues(se, se2, "static entropy round trips")

	// Remove just the entropy file.
	err = os.Remove(filepath.Join(tmpDir, FileP2PStaticEntropy))
	require.NoError(err, "Remove(FileP2PStaticEntropy)")

	// Load again, make sure entropy is regenerated but keys are equal.
	signer2, err = factory.Load(signature.SignerP2P)
	require.NoError(err, "LoadPEM(fn, nil), exists")
	require.NotEqual(signer, signer2, "Generated != Loaded")
	require.Equal(signer.Public(), signer2.Public(), "public keys are equal")
	se2, err = signer2.(signature.StaticEntropyProvider).StaticEntropy()
	require.NoError(err, "StaticEntropy()")
	require.NotEqual(se, se2, "static entropy is regenerated")
}
