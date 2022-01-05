package storage

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	"github.com/oasisprotocol/oasis-core/go/storage/tests"
)

func TestCrashingBackendDoNotInterfere(t *testing.T) {
	require := require.New(t)

	testNs := common.NewTestNamespaceFromSeed([]byte("crashing backend test ns"), 0)

	var (
		cfg = api.Config{
			Backend:      database.BackendNameBadgerDB,
			Namespace:    testNs,
			MaxCacheSize: 16 * 1024 * 1024,
		}
		err error
	)

	cfg.DB, err = ioutil.TempDir("", "crashing.test.badgerdb")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(cfg.DB)

	realBackend, err := database.New(&cfg)
	require.NoError(err, "database.New")
	backend := newCrashingWrapper(realBackend)

	crash.Config(map[string]float64{
		"storage.write.before": 0.0,
		"storage.write.after":  0.0,
		"storage.read.before":  0.0,
		"storage.read.after":   0.0,
	})

	genesisTestHelpers.SetTestChainContext()
	tests.StorageImplementationTests(t, backend, backend, testNs, 0)
}
