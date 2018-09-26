package bolt

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/internal/tester"

	bolt "go.etcd.io/bbolt"

	"golang.org/x/net/context"
)

func TestStorageBolt(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "ekiden-storage-bolt-test")
	require.NoError(t, err, "TempDir()")
	defer os.RemoveAll(tmpDir)

	timeSource := mock.New()
	backend, err := New(filepath.Join(tmpDir, DBFile), timeSource)
	require.NoError(t, err, "New()")
	defer backend.Cleanup()

	tester.StorageImplementationTest(t, backend, timeSource)
}

var (
	migrationTestValue      = []byte("Hello from an earlier schema.")
	migrationTestHash       = api.HashStorageKey(migrationTestValue)
	migrationTestExpiration = epochtime.EpochTime(100)
)

func setupV0(t *testing.T, fn string) {
	rawExp := epochTimeToRaw(migrationTestExpiration)

	db, err := bolt.Open(fn, 0600, nil)
	require.NoError(t, err, "setupV0 bolt.Open()")
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		bkt, err2 := tx.CreateBucket(bktMetadata)
		require.NoError(t, err2, "setupV0 tx.CreateBucket() metadata")
		err = bkt.Put(keyVersion, []byte{0x00})
		require.NoError(t, err, "setupV0 metadata bkt.Put() version")
		bkt, err = tx.CreateBucket([]byte("store"))
		require.NoError(t, err, "setupV0 tx.CreateBucket() store")
		bkt, err = bkt.CreateBucket(migrationTestHash[:])
		require.NoError(t, err, "setupV0 store bkt.CreateBucket() hash")
		err = bkt.Put([]byte("value"), migrationTestValue)
		require.NoError(t, err, "setupV0 store bkt.Put() value")
		err = bkt.Put([]byte("expiration"), rawExp)
		require.NoError(t, err, "setupV0 store bkt.Put() expiration")
		return nil
	})
	require.NoError(t, err, "setupV0 db.Update()")
}

func TestMigrationV0(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "ekiden-storage-bolt-test")
	require.NoError(t, err, "TempDir()")
	defer os.RemoveAll(tmpDir)
	fn := filepath.Join(tmpDir, DBFile)

	setupV0(t, fn)

	timeSource := mock.New()
	backend, err := New(fn, timeSource)
	require.NoError(t, err, "New()")
	defer backend.Cleanup()

	<-backend.Initialized()

	value, err := backend.Get(context.Background(), migrationTestHash)
	require.NoError(t, err, "Get v0")
	require.Equal(t, migrationTestValue, value, "Get v0")

	keyInfos, err := backend.GetKeys(context.Background())
	require.NoError(t, err, "GetKeys v0")
	require.Equal(t, []*api.KeyInfo{
		{Key: migrationTestHash, Expiration: migrationTestExpiration},
	}, keyInfos, "GetKeys v0")
}
