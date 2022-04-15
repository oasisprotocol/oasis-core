package committee

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/txsync"
)

func (n *Node) handleNewCheckedTransactions(txs []*txpool.PendingCheckTransaction) {
	// Check if we are waiting for new transactions.
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	state, ok := n.state.(StateWaitingForTxs)
	if !ok {
		return
	}

	for _, tx := range txs {
		delete(state.batch.missingTxs, tx.Hash())
	}
	if len(state.batch.missingTxs) == 0 {
		// We have all transactions, signal the node to start processing the batch.
		n.logger.Info("received all transactions needed for batch processing")
		n.startProcessingBatchLocked(state.batch)
	}
}

func (n *Node) requestMissingTransactions() {
	requestOp := func() error {
		// Determine what transactions are missing.
		txHashes := func() []hash.Hash {
			n.commonNode.CrossNode.Lock()
			defer n.commonNode.CrossNode.Unlock()

			state, ok := n.state.(StateWaitingForTxs)
			if !ok {
				return nil
			}

			txHashes := make([]hash.Hash, 0, len(state.batch.missingTxs))
			for txHash := range state.batch.missingTxs {
				txHashes = append(txHashes, txHash)
			}
			return txHashes
		}()
		if len(txHashes) == 0 {
			return nil
		}

		txCtx, cancel := context.WithCancel(n.roundCtx)
		defer cancel()

		rsp, err := n.txSync.GetTxs(txCtx, &txsync.GetTxsRequest{
			Txs: txHashes,
		})
		if err != nil {
			n.logger.Warn("failed to request missing transactions from peers",
				"err", err,
			)
			return err
		}

		n.logger.Debug("resolved (some) missing transactions",
			"resolved", len(rsp.Txs),
			"missing", len(txHashes),
		)

		if len(rsp.Txs) == 0 {
			n.logger.Debug("no peer returned transactions",
				"tx_hashes", txHashes,
			)
		}

		// Queue all transactions in the transaction pool.
		n.commonNode.TxPool.SubmitProposedBatch(rsp.Txs)

		// Check if there are still missing transactions and perform another request.
		if _, missingTxs := n.commonNode.TxPool.GetKnownBatch(txHashes); len(missingTxs) > 0 {
			return fmt.Errorf("need to resolve more transactions")
		}

		return nil
	}

	// Retry until we have resolved all transactions (or round context expires).
	boff := cmnBackoff.NewExponentialBackOff()
	boff.MaxInterval = 2 * time.Second
	err := backoff.Retry(requestOp, backoff.WithContext(boff, n.roundCtx))
	if err != nil {
		n.logger.Warn("failed to resolve missing transactions",
			"err", err,
		)
		return
	}

	// We have all transactions, signal the node to start processing the batch.
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	state, ok := n.state.(StateWaitingForTxs)
	if !ok {
		return
	}

	n.logger.Info("received all transactions needed for batch processing")
	n.startProcessingBatchLocked(state.batch)
}
