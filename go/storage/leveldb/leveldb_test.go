package leveldb

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

func TestStorageLevelDB(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "ekiden-storage-leveldb-test")
	require.NoError(t, err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	timeSource := mock.New()
	pk, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey()")

	backend, err := New(filepath.Join(tmpDir, DBFile), filepath.Join(tmpDir, MKVSDBFile), timeSource, &pk, 32*1024*1024, 100)
	require.NoError(t, err, "New()")
	defer backend.Cleanup()

	tests.StorageImplementationTests(t, backend, timeSource, false)
}
