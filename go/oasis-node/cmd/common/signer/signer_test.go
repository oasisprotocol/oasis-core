package signer

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestCompositeCtor(t *testing.T) {
	require := require.New(t)

	dataDir, err := ioutil.TempDir("", "oasis-node-test_signer_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	viper.Set(cfgSignerCompositeBackends, "node:file,consensus:memory")
	defer viper.Set(cfgSignerCompositeBackends, "")

	testingAllowMemory = true

	sf, err := doNewComposite(dataDir, signature.SignerNode, signature.SignerConsensus)
	require.NoError(err, "doNewComposite")

	err = sf.EnsureRole(signature.SignerEntity)
	require.Equal(signature.ErrRoleMismatch, err, "EnsureRole: not configured (entity)")

	err = sf.EnsureRole(signature.SignerNode)
	require.NoError(err, "EnsureRole: file")

	err = sf.EnsureRole(signature.SignerP2P)
	require.Equal(signature.ErrRoleMismatch, err, "EnsureRole: not configured (p2p)")

	err = sf.EnsureRole(signature.SignerVRF)
	require.Equal(signature.ErrRoleMismatch, err, "EnsureRole: not configured (VRF)")

	err = sf.EnsureRole(signature.SignerConsensus)
	require.NoError(err, "EnsureRole: memory")

	signer, err := sf.Generate(signature.SignerNode, rand.Reader)
	require.NoError(err, "Generate: file")
	require.IsType(&fileSigner.Signer{}, signer, "Generate: file")

	signer2, err := sf.Generate(signature.SignerConsensus, rand.Reader)
	require.NoError(err, "Generate: memory")
	require.IsType(&memorySigner.Signer{}, signer2, "Generate: memory")
}
