package database

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/tests"
)

func TestStorageDatabase(t *testing.T) {
	for _, v := range []string{
		BackendNameBadgerDB,
		BackendNamePathBadger,
	} {
		t.Run(v, func(t *testing.T) {
			doTestImpl(t, v)
		})
	}
}

func doTestImpl(t *testing.T, backend string) {
	require := require.New(t)

	testNs := common.NewTestNamespaceFromSeed([]byte("database backend test ns"), 0)

	var (
		cfg = api.Config{
			Backend:      backend,
			Namespace:    testNs,
			MaxCacheSize: 16 * 1024 * 1024,
			NoFsync:      true,
		}
		err error
	)

	cfg.DB, err = os.MkdirTemp("", "oasis-storage-database-test")
	require.NoError(err, "TempDir()")
	defer os.RemoveAll(cfg.DB)

	cfg.DB = filepath.Join(cfg.DB, DefaultFileName(backend))
	impl, err := New(&cfg)
	require.NoError(err, "New()")
	defer impl.Cleanup()

	genesisTestHelpers.SetTestChainContext()
	tests.StorageImplementationTests(t, impl, impl, testNs, 0)
}

func TestAutoBackend(t *testing.T) {
	t.Run("NoExistingDir", func(t *testing.T) {
		require := require.New(t)

		tmpDir, err := os.MkdirTemp("", "oasis-storage-database-test")
		require.NoError(err, "TempDir()")
		defer os.RemoveAll(tmpDir)

		// When there is no existing database directory, the default should be used.
		cfg := api.Config{
			Backend: "auto",
			DB:      filepath.Join(tmpDir, DefaultFileName("auto")),
		}
		impl, err := New(&cfg)
		require.NoError(err)
		impl.Cleanup()

		require.Equal(defaultBackendName, cfg.Backend)
		require.Equal(filepath.Join(tmpDir, DefaultFileName(defaultBackendName)), cfg.DB)
	})

	t.Run("OneExistingDir", func(t *testing.T) {
		require := require.New(t)

		tmpDir, err := os.MkdirTemp("", "oasis-storage-database-test")
		require.NoError(err, "TempDir()")
		defer os.RemoveAll(tmpDir)

		// Create a badger database first.
		cfg := api.Config{
			Backend: "badger",
			DB:      filepath.Join(tmpDir, DefaultFileName("badger")),
		}
		impl, err := New(&cfg)
		require.NoError(err)
		impl.Cleanup()

		// When there is an existing backend, it should be used.
		cfg = api.Config{
			Backend: "auto",
			DB:      filepath.Join(tmpDir, DefaultFileName("auto")),
		}
		impl, err = New(&cfg)
		require.NoError(err)
		impl.Cleanup()

		require.Equal("badger", cfg.Backend)
		require.Equal(filepath.Join(tmpDir, DefaultFileName("badger")), cfg.DB)
	})

	t.Run("MultiExistingDirs", func(t *testing.T) {
		require := require.New(t)

		tmpDir, err := os.MkdirTemp("", "oasis-storage-database-test")
		require.NoError(err, "TempDir()")
		defer os.RemoveAll(tmpDir)

		// Create a badger database first.
		cfg := api.Config{
			Backend: "badger",
			DB:      filepath.Join(tmpDir, DefaultFileName("badger")),
		}
		impl, err := New(&cfg)
		require.NoError(err)
		impl.Cleanup()

		// Then create a pathbadger database.
		cfg = api.Config{
			Backend: "pathbadger",
			DB:      filepath.Join(tmpDir, DefaultFileName("pathbadger")),
		}
		impl, err = New(&cfg)
		require.NoError(err)
		impl.Cleanup()

		// When there are multiple existing backends, the most recent one should be used.
		cfg = api.Config{
			Backend: "auto",
			DB:      filepath.Join(tmpDir, DefaultFileName("auto")),
		}
		impl, err = New(&cfg)
		require.NoError(err)
		impl.Cleanup()

		require.Equal("pathbadger", cfg.Backend)
		require.Equal(filepath.Join(tmpDir, DefaultFileName("pathbadger")), cfg.DB)
	})
}
