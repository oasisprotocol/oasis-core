package committee

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/txsync"
)

// Guarded by n.commonNode.CrossNode.
func (n *Node) resolveBatchLocked(batch *unresolvedBatch, missingState NodeState) (transaction.RawBatch, error) {
	n.logger.Debug("attempting to resolve batch", "batch", batch.String())

	// TODO: Add metrics for how long it takes to receive the complete batch.
	if batch.proposal != nil {
		n.commonNode.TxPool.PromoteProposedBatch(batch.proposal.Batch)
	}
	resolvedBatch, err := batch.resolve(n.commonNode.TxPool)
	if err != nil {
		n.logger.Error("refusing to process bad batch", "err", err)
		// TODO: We should indicate failure.
		return nil, err
	}
	if resolvedBatch == nil {
		// Some transactions are missing so we cannot start processing the batch just yet.
		// Request transactions from peers.
		n.logger.Debug("some transactions are missing", "num_missing", len(batch.missingTxs))
		n.transitionLocked(missingState)

		if n.missingTxsCancel != nil {
			n.missingTxsCancel() // Cancel any outstanding requests.
		}
		var ctx context.Context
		ctx, n.missingTxsCancel = context.WithCancel(n.roundCtx)
		go n.requestMissingTransactions(ctx)
	}
	return resolvedBatch, nil
}

// getBatchFromState extracts an unresolved batch from the given node state.
//
// If the state does not contain an unresolved batch, nil is returned.
func getBatchFromState(state NodeState) (batch *unresolvedBatch, isWaitingEv bool) {
	switch s := state.(type) {
	case StateWaitingForTxs:
		batch = s.batch
	case StateWaitingForEvent:
		batch = s.batch
		isWaitingEv = true
	default:
	}
	return
}

func (n *Node) handleNewCheckedTransactions(txs []*txpool.PendingCheckTransaction) {
	// Check if we are waiting for new transactions.
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	batch, isWaitingEv := getBatchFromState(n.state)
	if batch == nil {
		return
	}

	for _, tx := range txs {
		delete(batch.missingTxs, tx.Hash())
	}
	if len(batch.missingTxs) == 0 {
		// We have all transactions, signal the node to start processing the batch.
		n.logger.Info("received all transactions needed for batch processing")
		if !isWaitingEv {
			n.startProcessingBatchLocked(batch)
		}
	}
}

func (n *Node) requestMissingTransactions(ctx context.Context) {
	requestOp := func() error {
		// Determine what transactions are missing.
		txHashes := func() []hash.Hash {
			n.commonNode.CrossNode.Lock()
			defer n.commonNode.CrossNode.Unlock()

			batch, _ := getBatchFromState(n.state)
			if batch == nil {
				return nil
			}

			txHashes := make([]hash.Hash, 0, len(batch.missingTxs))
			for txHash := range batch.missingTxs {
				txHashes = append(txHashes, txHash)
			}
			return txHashes
		}()
		if len(txHashes) == 0 {
			return nil
		}

		rsp, err := n.txSync.GetTxs(ctx, &txsync.GetTxsRequest{
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
	err := backoff.Retry(requestOp, backoff.WithContext(boff, ctx))
	if err != nil {
		n.logger.Warn("failed to resolve missing transactions",
			"err", err,
		)
		return
	}

	// We have all transactions, signal the node to start processing the batch.
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	batch, isWaitingEv := getBatchFromState(n.state)
	if batch == nil {
		return
	}

	n.logger.Info("received all transactions needed for batch processing")
	if !isWaitingEv {
		n.startProcessingBatchLocked(batch)
	}
}
