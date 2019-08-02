package tendermint

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
)

func TestBlockIndexer(t *testing.T) {
	// Create a new random temporary directory under /tmp.
	dataDir, err := ioutil.TempDir("", "ekiden-roothash-block-idx-test_")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dataDir)

	idx, err := newBlockIndex(dataDir)
	require.NoError(t, err, "newBlockIndex")

	var id signature.PublicKey
	_ = id.UnmarshalBinary(make([]byte, signature.PublicKeySize))
	_, err = idx.GetBlockHeight(id, 0)
	require.Error(t, err, "GetBlockHeight")

	blk := block.NewGenesisBlock(id, 1234)
	err = idx.Index(blk, 42)
	require.NoError(t, err, "Index")

	height, err := idx.GetLastHeight()
	require.NoError(t, err, "GetLastHeight")
	require.EqualValues(t, 42, height, "GetLastHeight")

	height, err = idx.GetBlockHeight(id, 0)
	require.NoError(t, err, "GetBlockHeight")
	require.EqualValues(t, 42, height, "GetBlockHeight")

	pruned, err := idx.Prune(42)
	require.NoError(t, err, "Prune")
	require.Len(t, pruned, 1)
	require.EqualValues(t, pruned[0].RuntimeID, id)
	require.EqualValues(t, pruned[0].Round, 0)
	_, err = idx.GetBlockHeight(id, 0)
	require.Error(t, err, "GetBlockHeight")
}
