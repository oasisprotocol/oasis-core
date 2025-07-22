package txpool

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

var testTransactionID int64

func newTestTransaction(sender int, seq uint64, priority uint64) *mainQueueTransaction {
	id := atomic.AddInt64(&testTransactionID, 1)
	raw := []byte(fmt.Sprintf("transaction-%d", id))
	tx := TxQueueMeta{
		raw:       raw,
		hash:      hash.NewFromBytes(raw),
		firstSeen: time.Now(),
	}
	return newMainQueueTransaction(&tx, fmt.Sprintf("sender-%d", sender), seq, priority)
}

func testExtractMetaTransactions() []*TxQueueMeta {
	metas := make([]*TxQueueMeta, 0)
	for _, tx := range testTxs {
		metas = append(metas, tx.meta)
	}
	return metas
}

func testPrepareSchedule() []*TxQueueMeta {
	return []*TxQueueMeta{
		testMetaTxs[8],
		testMetaTxs[7],
		testMetaTxs[0],
		testMetaTxs[1],
		testMetaTxs[6],
		testMetaTxs[5],
	}
}

func testPrepareMainQueueScheduler(capacity int, txs []*mainQueueTransaction) (*mainQueueScheduler, error) {
	s := newMainQueueScheduler(capacity)
	for _, tx := range txs {
		if err := s.add(tx, 0); err != nil {
			return nil, err
		}
	}
	return s, nil
}

var (
	testTxs = []*mainQueueTransaction{
		// First sender.
		newTestTransaction(0, 0, 50),
		newTestTransaction(0, 1, 90),
		newTestTransaction(0, 8, 30),
		newTestTransaction(0, 5, 60),
		newTestTransaction(0, 6, 10),
		// Second sender.
		newTestTransaction(1, 2, 40),
		newTestTransaction(1, 1, 20),
		newTestTransaction(1, 0, 70),
		// Third sender.
		newTestTransaction(2, 0, 80),
		// Forth sender.
		newTestTransaction(3, 1, 0),
	}

	testMetaTxs  = testExtractMetaTransactions()
	testSchedule = testPrepareSchedule()
)

func TestSize(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		require.Equal(t, 0, s.size())
	})

	t.Run("Non-empty", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		require.Equal(t, len(testTxs), s.size())
	})
}

func TestGet(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		_, ok := s.get(testTxs[0].meta.hash)
		require.False(t, ok)
	})

	t.Run("Exists", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		tx, ok := s.get(testTxs[0].meta.hash)
		require.True(t, ok)
		require.Equal(t, testTxs[0], tx)
	})

	t.Run("Missing", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs[1:])
		require.NoError(t, err)

		_, ok := s.get(testTxs[0].meta.hash)
		require.False(t, ok)
	})
}

func TestAll(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		txs := s.all()
		require.Equal(t, 0, len(txs))
		require.Equal(t, 0, s.size())
	})

	t.Run("Non-empty", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		txs := s.all()
		require.Equal(t, len(testTxs), len(txs))
		require.ElementsMatch(t, testMetaTxs, txs)
		require.Equal(t, len(testTxs), s.size())
	})
}

func TestClear(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		s.clear()
		require.Equal(t, 0, s.size())
	})

	t.Run("Non-empty", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		s.clear()
		require.Equal(t, 0, s.size())
	})
}

func TestDrain(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		txs := s.drain()
		require.Equal(t, 0, len(txs))
		require.Equal(t, 0, s.size())
	})

	t.Run("Non-empty", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		txs := s.drain()
		require.Equal(t, len(testTxs), len(txs))
		require.ElementsMatch(t, testMetaTxs, txs)
		require.Equal(t, 0, s.size())
	})
}

func TestAdd(t *testing.T) {
	t.Run("Multiple transactions", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		for i, tx := range testTxs {
			err := s.add(tx, 0)
			require.NoError(t, err)
			require.Equal(t, i+1, s.size())

			tx, ok := s.get(tx.meta.hash)
			require.True(t, ok)
			require.Equal(t, tx, tx)
		}
	})

	t.Run("Duplicate transaction", func(t *testing.T) {
		s := newMainQueueScheduler(10)
		tx := newTestTransaction(0, 0, 0)

		// Add transaction.
		err := s.add(tx, 0)
		require.NoError(t, err)
		require.Equal(t, 1, s.size())

		tx, ok := s.get(tx.meta.hash)
		require.True(t, ok)
		require.Equal(t, tx, tx)

		// Add transaction again.
		err = s.add(tx, 0)
		require.Error(t, err)
		require.ErrorContains(t, err, "replacement transaction underpriced")
		require.Equal(t, 1, s.size())
	})

	t.Run("Replace transaction", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		// Transactions with the same sequence number but different priorities.
		txs := []*mainQueueTransaction{
			newTestTransaction(0, 0, 1),
			newTestTransaction(0, 0, 0), // Lower priority.
			newTestTransaction(0, 0, 2), // Higher priority.
		}

		// Add the first transaction.
		err := s.add(txs[0], 0)
		require.NoError(t, err)
		require.Equal(t, 1, s.size())

		tx, ok := s.get(txs[0].meta.hash)
		require.True(t, ok)
		require.Equal(t, txs[0], tx)

		// Add transaction with lower priority.
		err = s.add(txs[1], 0)
		require.Error(t, err)
		require.ErrorContains(t, err, "replacement transaction underpriced")
		require.Equal(t, 1, s.size())

		_, ok = s.get(txs[1].meta.hash)
		require.False(t, ok)

		// Add transaction with higher priority.
		err = s.add(txs[2], 0)
		require.NoError(t, err)
		require.Equal(t, 1, s.size())

		tx, ok = s.get(txs[2].meta.hash)
		require.True(t, ok)
		require.Equal(t, txs[2], tx)

		// Verify final state.
		_, ok = s.get(txs[0].meta.hash)
		require.False(t, ok)

		_, ok = s.get(txs[1].meta.hash)
		require.False(t, ok)

		_, ok = s.get(txs[2].meta.hash)
		require.True(t, ok)
	})

	t.Run("Full queue", func(t *testing.T) {
		s := newMainQueueScheduler(5)

		// Fill the queue.
		txs := make([]*mainQueueTransaction, 0, 5)
		for i := range uint64(5) {
			tx := newTestTransaction(0, i, 10)
			txs = append(txs, tx)
		}
		for _, tx := range txs {
			err := s.add(tx, 0)
			require.NoError(t, err)
		}

		// Accept transaction with higher priority.
		tx := newTestTransaction(0, 2, 100)
		err := s.add(tx, 0)
		require.NoError(t, err)

		actual, ok := s.get(tx.meta.hash)
		require.True(t, ok)
		require.Equal(t, tx, actual)

		_, ok = s.get(txs[2].meta.hash)
		require.False(t, ok)

		// Reject transaction with lower priority.
		tx = newTestTransaction(0, 6, 0)
		err = s.add(tx, 0)
		require.Error(t, err)
		require.ErrorContains(t, err, "transaction underpriced")
	})
}

func TestForward(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		s.forward(testTxs[0].sender, 10)
		require.Equal(t, 0, s.size())
	})

	t.Run("Non-existing", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		s.forward("unknown", 0)
		require.Equal(t, len(testTxs), s.size())
	})

	t.Run("Remove none", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		s.forward(testTxs[0].sender, 0)
		require.Equal(t, len(testTxs), s.size())
	})

	t.Run("Remove few", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		s.forward(testTxs[0].sender, 2)
		require.Equal(t, len(testTxs)-2, s.size())
	})

	t.Run("Remove all", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		s.forward(testTxs[0].sender, 100)
		require.Equal(t, len(testTxs)-5, s.size())
	})
}

func TestHandleTxUsed(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		hash := hash.Hash{1}
		s.handleTxUsed(hash)
		require.Equal(t, 0, s.size())
	})

	t.Run("Non-existing", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		hash := hash.Hash{1}
		s.handleTxUsed(hash)
		require.Equal(t, len(testTxs), s.size())
	})

	t.Run("First pending", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		hash := testTxs[0].meta.hash
		s.handleTxUsed(hash)
		require.Equal(t, len(testTxs)-1, s.size())
	})

	t.Run("Second pending", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		hash := testTxs[1].meta.hash
		s.handleTxUsed(hash)
		require.Equal(t, len(testTxs)-2, s.size())
	})
}

func TestSchedule(t *testing.T) {
	t.Run("None", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		txs := s.schedule(0)
		require.Equal(t, 0, len(txs))
		require.Equal(t, testSchedule[:0], txs)
	})

	t.Run("Few", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		txs := s.schedule(2)
		require.Equal(t, 2, len(txs))
		require.Equal(t, testSchedule[:2], txs)
	})

	t.Run("All", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		txs := s.schedule(100)
		require.Equal(t, len(testSchedule), len(txs))
		require.Equal(t, testSchedule, txs)
	})

	t.Run("Extra", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		txs := s.schedule(1)
		require.Equal(t, 1, len(txs))
		require.Equal(t, testSchedule[:1], txs)

		extra := s.schedule(2)
		txs = append(txs, extra...)
		require.Equal(t, 3, len(txs))
		require.Equal(t, testSchedule[:3], txs)

		extra = s.schedule(100)
		txs = append(txs, extra...)
		require.Equal(t, len(testSchedule), len(txs))
		require.Equal(t, testSchedule, txs)
	})
}

func TestReset(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		s := newMainQueueScheduler(10)

		s.reset()
		s.reset()
	})

	t.Run("Reset", func(t *testing.T) {
		s, err := testPrepareMainQueueScheduler(10, testTxs)
		require.NoError(t, err)

		for range 1 {
			txs := s.schedule(3)
			require.Equal(t, 3, len(txs))
			require.Equal(t, testSchedule[:3], txs)

			s.reset()
		}
	})
}
