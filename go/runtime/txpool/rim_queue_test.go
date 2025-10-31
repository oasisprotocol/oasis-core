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

	tx, ok := rq.Get(txA.Hash())
	require.True(t, ok, "get tx by hash a")
	require.EqualValues(t, txA, tx, "get tx by hash a")
	hashC := hash.NewFromBytes([]byte("c"))
	tx, ok = rq.Get(hashC)
	require.False(t, ok, "get tx by hash c")
	require.Nil(t, tx, "get tx by hash c")
}
