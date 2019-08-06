package badger

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

var testNs common.Namespace

func TestStorageBadger(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "ekiden-storage-leveldb-test")
	require.NoError(t, err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewPrivateKey()")

	backend, err := New(filepath.Join(tmpDir, DBFile), signer, 100, false)
	require.NoError(t, err, "New()")
	defer backend.Cleanup()

	tests.StorageImplementationTests(t, backend, testNs)
}

func init() {
	var ns hash.Hash
	ns.FromBytes([]byte("ekiden storage badger test ns"))
	copy(testNs[:], ns[:])
}
