package database

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
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

var testNs common.Namespace

func TestStorageDatabase(t *testing.T) {
	for _, v := range []string{
		BackendNameLevelDB,
		BackendNameBadgerDB,
	} {
		t.Run(v, func(t *testing.T) {
			doTestImpl(t, v)
		})
	}
}

func doTestImpl(t *testing.T, backend string) {
	require := require.New(t)

	var (
		cfg = api.Config{
			Backend:           backend,
			ApplyLockLRUSlots: 100,
		}
		err error
	)

	cfg.Signer, err = memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner()")

	cfg.DB, err = ioutil.TempDir("", "ekiden-storage-database-test")
	require.NoError(err, "TempDir()")
	defer os.RemoveAll(cfg.DB)

	cfg.DB = filepath.Join(cfg.DB, DefaultFileName(backend))
	impl, err := New(&cfg)
	require.NoError(err, "New()")
	defer impl.Cleanup()

	tests.StorageImplementationTests(t, impl, testNs)
}

func init() {
	var ns hash.Hash
	ns.FromBytes([]byte("ekiden storage badger test ns"))
	copy(testNs[:], ns[:])
}
