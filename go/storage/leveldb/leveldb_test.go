package leveldb

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

func TestStorageLevelDB(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "ekiden-storage-leveldb-test")
	require.NoError(t, err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	timeSource := mock.New()
	backend, err := New(filepath.Join(tmpDir, DBFile), timeSource, nil)
	require.NoError(t, err, "New()")
	defer backend.Cleanup()

	tests.StorageImplementationTests(t, backend, timeSource, false)
}
