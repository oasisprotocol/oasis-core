package storage

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crash"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/database"
	"github.com/oasislabs/oasis-core/go/storage/tests"
)

var testNs common.Namespace

func TestCrashingBackendDoNotInterfere(t *testing.T) {
	require := require.New(t)

	var (
		cfg = api.Config{
			Backend:      database.BackendNameBadgerDB,
			Namespace:    testNs,
			MaxCacheSize: 16 * 1024 * 1024,
		}
		err error
	)

	cfg.Signer, err = memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner()")

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

	tests.StorageImplementationTests(t, backend, testNs, 0)
}

func init() {
	var ns hash.Hash
	ns.FromBytes([]byte("oasis storage crashing test ns"))
	copy(testNs[:], ns[:])
}
