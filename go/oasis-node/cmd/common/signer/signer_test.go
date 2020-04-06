package signer

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestCompositeCtor(t *testing.T) {
	require := require.New(t)

	dataDir, err := ioutil.TempDir("", "oasis-node-test_signer_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	viper.Set(cfgSignerCompositeBackends, "1:ledger,2:file,4:memory")
	defer viper.Set(cfgSignerCompositeBackends, "")

	testingAllowMemory = true

	sf, err := doNewComposite(dataDir, signature.SignerEntity, signature.SignerNode, signature.SignerConsensus)
	require.NoError(err, "doNewComposite")

	err = sf.EnsureRole(signature.SignerEntity)
	require.NoError(err, "EnsureRole: ledger")

	err = sf.EnsureRole(signature.SignerNode)
	require.NoError(err, "EnsureRole: file")

	err = sf.EnsureRole(signature.SignerP2P)
	require.Equal(signature.ErrRoleMismatch, err, "EnsureRole: not configured")

	err = sf.EnsureRole(signature.SignerConsensus)
	require.NoError(err, "EnsureRole: memory")

	// Can't actually generate with the ledger backend, because most systems
	// do not have that garbage.

	signer, err := sf.Generate(signature.SignerNode, rand.Reader)
	require.NoError(err, "Generate: file")
	require.IsType(&fileSigner.Signer{}, signer, "Generate: file")

	signer2, err := sf.Generate(signature.SignerConsensus, rand.Reader)
	require.NoError(err, "Generate: memory")
	require.IsType(&memorySigner.Signer{}, signer2, "Generate: memory")
}
