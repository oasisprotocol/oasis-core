package abci

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	mkvsDB "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	mkvsBadgerDB "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

func TestPruneKeepN(t *testing.T) {
	require := require.New(t)

	// Create a new random temporary directory under /tmp.
	dir, err := ioutil.TempDir("", "abci-prune.test.badger")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	// Create a Badger-backed Node DB.
	ndb, err := mkvsBadgerDB.New(&mkvsDB.Config{
		DB:           dir,
		NoFsync:      true,
		MaxCacheSize: 16 * 1024 * 1024,
	})
	require.NoError(err, "New")
	tree := mkvs.New(nil, ndb, mkvsNode.RootTypeState)

	ctx := context.Background()
	for i := uint64(1); i <= 11; i++ {
		err = tree.Insert(ctx, []byte(fmt.Sprintf("key:%d", i)), []byte(fmt.Sprintf("value:%d", i)))
		require.NoError(err, "Insert")

		var rootHash hash.Hash
		_, rootHash, err = tree.Commit(ctx, common.Namespace{}, i)
		require.NoError(err, "Commit")
		err = ndb.Finalize(ctx, []mkvsNode.Root{{Namespace: common.Namespace{}, Version: i, Type: mkvsNode.RootTypeState, Hash: rootHash}})
		require.NoError(err, "Finalize")
	}

	earliestVersion, err := ndb.GetEarliestVersion(ctx)
	require.NoError(err, "GetEarliestVersion")
	require.EqualValues(1, earliestVersion, "earliest version should be correct")
	latestVersion, err := ndb.GetLatestVersion(ctx)
	require.NoError(err, "GetLatestVersion")
	require.EqualValues(11, latestVersion, "latest version should be correct")

	pruner, err := newStatePruner(&PruneConfig{
		Strategy: PruneKeepN,
		NumKept:  2,
	}, ndb, 10)
	require.NoError(err, "newStatePruner failed")

	earliestVersion, err = ndb.GetEarliestVersion(ctx)
	require.NoError(err, "GetEarliestVersion")
	require.EqualValues(8, earliestVersion, "earliest version should be correct")
	latestVersion, err = ndb.GetLatestVersion(ctx)
	require.NoError(err, "GetLatestVersion")
	require.EqualValues(11, latestVersion, "latest version should be correct")

	lastRetainedVersion := pruner.GetLastRetainedVersion()
	require.EqualValues(8, lastRetainedVersion, "last retained version should be correct")

	err = pruner.Prune(ctx, 11)
	require.NoError(err, "Prune")

	earliestVersion, err = ndb.GetEarliestVersion(ctx)
	require.NoError(err, "GetEarliestVersion")
	require.EqualValues(9, earliestVersion, "earliest version should be correct")
	latestVersion, err = ndb.GetLatestVersion(ctx)
	require.NoError(err, "GetLatestVersion")
	require.EqualValues(11, latestVersion, "latest version should be correct")

	lastRetainedVersion = pruner.GetLastRetainedVersion()
	require.EqualValues(9, lastRetainedVersion, "last retained version should be correct")
}
