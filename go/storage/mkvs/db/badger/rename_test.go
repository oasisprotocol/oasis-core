package badger

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

func TestRenameNamespace(t *testing.T) {
	require := require.New(t)

	srcNs := common.NewTestNamespaceFromSeed([]byte("badger node db test ns 1"), 0)
	dstNs := common.NewTestNamespaceFromSeed([]byte("badger node db test ns 2"), 0)

	// Create a new random temporary directory under /tmp.
	dir, err := ioutil.TempDir("", "mkvs.test.badger")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	dbCfg = &api.Config{
		DB:           dir,
		Namespace:    srcNs,
		MaxCacheSize: 16 * 1024 * 1024,
		NoFsync:      true,
	}

	ndb, err := New(dbCfg)
	require.NoError(err, "New(srcNs)")
	ndb.Close()

	err = RenameNamespace(dbCfg, dstNs)
	require.NoError(err, "RenameNamespace")

	_, err = New(dbCfg)
	require.Error(err, "New(srcNs) should fail on renamed database")

	dbCfg.Namespace = dstNs

	ndb, err = New(dbCfg)
	require.NoError(err, "New(dstNs)")
	ndb.Close()
}
