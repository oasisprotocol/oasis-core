package abci

import (
	"context"
	"fmt"
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
	dir := t.TempDir()

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
		err = ndb.Finalize([]mkvsNode.Root{{Namespace: common.Namespace{}, Version: i, Type: mkvsNode.RootTypeState, Hash: rootHash}})
		require.NoError(err, "Finalize")
	}

	earliestVersion := ndb.GetEarliestVersion()
	require.EqualValues(1, earliestVersion, "earliest version should be correct")
	latestVersion, exists := ndb.GetLatestVersion()
	require.EqualValues(11, latestVersion, "latest version should be correct")
	require.True(exists, "latest version should exist")

	pruner, err := newStatePruner(&PruneConfig{
		Strategy: PruneKeepN,
		NumKept:  2,
	}, ndb)
	require.NoError(err, "newStatePruner failed")

	earliestVersion = ndb.GetEarliestVersion()
	require.EqualValues(1, earliestVersion, "earliest version should be correct")
	latestVersion, exists = ndb.GetLatestVersion()
	require.EqualValues(11, latestVersion, "latest version should be correct")
	require.True(exists, "latest version should exist")

	lastRetainedVersion := pruner.GetLastRetainedVersion()
	require.EqualValues(1, lastRetainedVersion, "last retained version should be correct")

	err = pruner.Prune(11)
	require.NoError(err, "Prune")

	earliestVersion = ndb.GetEarliestVersion()
	require.EqualValues(9, earliestVersion, "earliest version should be correct")
	latestVersion, exists = ndb.GetLatestVersion()
	require.EqualValues(11, latestVersion, "latest version should be correct")
	require.True(exists, "latest version should exist")

	lastRetainedVersion = pruner.GetLastRetainedVersion()
	require.EqualValues(9, lastRetainedVersion, "last retained version should be correct")
}
