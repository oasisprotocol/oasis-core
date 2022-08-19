package txpool

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

func TestRimQueue(t *testing.T) {
	rq := newRimQueue()

	rawA := []byte("a")
	txA := &TxQueueMeta{raw: rawA, hash: hash.NewFromBytes(rawA)}
	rq.Load([]*message.IncomingMessage{
		{
			ID:   1,
			Data: rawA,
		},
	})
	require.EqualValues(t, map[hash.Hash]*TxQueueMeta{txA.Hash(): txA}, rq.txs, "after load")
	require.Equal(t, 1, rq.size())

	require.Nil(t, rq.GetSchedulingSuggestion(50), "get scheduling suggestion")
	rq.HandleTxsUsed([]hash.Hash{txA.Hash()})

	tx := rq.GetTxByHash(txA.Hash())
	require.EqualValues(t, txA, tx, "get tx by hash a")
	hashC := hash.NewFromBytes([]byte("c"))
	tx = rq.GetTxByHash(hashC)
	require.Nil(t, tx, "get tx by hash c")
}
