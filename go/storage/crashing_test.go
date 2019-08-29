package storage

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crash"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/database"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

var testNs common.Namespace

func TestCrashingBackendDoNotInterfere(t *testing.T) {
	require := require.New(t)

	var (
		cfg = api.Config{
			Backend: database.BackendNameLevelDB,
		}
		err error
	)

	cfg.Signer, err = memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner()")

	cfg.DB, err = ioutil.TempDir("", "crashing.test.leveldb")
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

	tests.StorageImplementationTests(t, backend, testNs)
}

func init() {
	var ns hash.Hash
	ns.FromBytes([]byte("ekiden storage crashing test ns"))
	copy(testNs[:], ns[:])
}
