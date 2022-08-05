package txpool

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

func TestLocalQueueBasic(t *testing.T) {
	lq := newLocalQueue()

	require.Len(t, lq.GetSchedulingSuggestion(50), 0, "get scheduling suggestion")

	// Add two transactions, with a higher priority one coming later.
	rawA := []byte("a")
	txA := &TxQueueMeta{Raw: rawA, Hash: hash.NewFromBytes(rawA)}
	require.NoError(t, lq.OfferChecked(txA, &protocol.CheckTxMetadata{Priority: 1}), "offer checked a")
	rawB := []byte("b")
	txB := &TxQueueMeta{Raw: rawB, Hash: hash.NewFromBytes(rawB)}
	require.NoError(t, lq.OfferChecked(txB, &protocol.CheckTxMetadata{Priority: 5}), "offer checked a")

	// We should preserve the order. Publish in original order.
	require.EqualValues(t, []*TxQueueMeta{txA, txB}, lq.GetTxsToPublish(), "get txs to publish")
	// Schedule in original order.
	require.EqualValues(t, []*TxQueueMeta{txA, txB}, lq.GetSchedulingSuggestion(50), "get scheduling suggestion")

	tx, ok := lq.GetTxByHash(txA.Hash)
	require.True(t, ok, "get tx by hash a")
	require.EqualValues(t, txA, tx, "get tx by hash a")
	hashC := hash.NewFromBytes([]byte("c"))
	tx, ok = lq.GetTxByHash(hashC)
	require.False(t, ok, "get tx by hash c")
	require.Nil(t, tx, "get tx by hash c")

	lq.HandleTxsUsed([]hash.Hash{hashC})
	require.EqualValues(t, map[hash.Hash]int{txA.Hash: 0, txB.Hash: 1}, lq.indexesByHash, "after handle txs used absent")
	lq.HandleTxsUsed([]hash.Hash{txA.Hash})
	require.EqualValues(t, map[hash.Hash]int{txB.Hash: 0}, lq.indexesByHash, "after handle txs used")

	require.EqualValues(t, []*TxQueueMeta{txB}, lq.TakeAll(), "take all")
	require.Len(t, lq.GetSchedulingSuggestion(50), 0, "after take all")
}
