package leveldb

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

func TestStorageLevelDB(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "ekiden-storage-leveldb-test")
	require.NoError(t, err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner()")

	backend, err := New(filepath.Join(tmpDir, DBFile), signer, 32*1024*1024, 100, false)
	require.NoError(t, err, "New()")
	defer backend.Cleanup()

	tests.StorageImplementationTests(t, backend)
}
