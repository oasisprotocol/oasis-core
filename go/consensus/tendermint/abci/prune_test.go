package abci

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/iavl"
	dbm "github.com/tendermint/tm-db"
)

func TestPruneKeepN(t *testing.T) {
	db := dbm.NewMemDB()
	tree := iavl.NewMutableTree(db, 128)

	for i := int64(1); i <= 11; i++ {
		tree.Set([]byte(fmt.Sprintf("key:%d", i)), []byte(fmt.Sprintf("value:%d", i)))
		_, ver, err := tree.SaveVersion()
		require.NoError(t, err, "SaveVersion: %d", i)
		require.Equal(t, i, ver, "incorrect version on save")
	}

	pruner, err := newStatePruner(&PruneConfig{
		Strategy: PruneKeepN,
		NumKept:  2,
	}, tree, 10)
	require.NoError(t, err, "newStatePruner failed")

	for i := int64(1); i <= 10; i++ {
		require.Equal(t, i >= 8, tree.VersionExists(i), "VersionExists(%d)", i)
	}

	pruner.Prune(11)
	require.False(t, tree.VersionExists(8), "VersionExists(8), should be pruned")
	require.True(t, tree.VersionExists(11), "VersionExists(11)")
}
