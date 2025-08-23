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
	state, ok := n.state.(StateWaitingForTxs)
	if !ok {
		return
	}

	for _, tx := range txs {
		h := tx.Hash()
		idx, ok := state.txs[h]
		if !ok {
			continue
		}
		delete(state.txs, h)
		state.batch[idx] = tx.Raw()
		state.bytes += uint64(tx.Size())
	}

	n.checkWaitingForTxsState(&state)
}

func (n *Node) handleMissingTransactions(txs [][]byte) {
	state, ok := n.state.(StateWaitingForTxs)
	if !ok {
		return
	}

	for _, tx := range txs {
		h := hash.NewFromBytes(tx)
		idx, ok := state.txs[h]
		if !ok {
			continue
		}
		delete(state.txs, h)
		state.batch[idx] = tx
		state.bytes += uint64(len(tx))
	}

	n.checkWaitingForTxsState(&state)
}

func (n *Node) checkWaitingForTxsState(state *StateWaitingForTxs) {
	if len(state.txs) == 0 {
		n.logger.Info("received all transactions needed for batch processing")
	}

	// The error will be addressed latter when the state will be updated.
	if state.maxBytes > 0 && state.bytes > state.maxBytes {
		n.logger.Info("the size of received transactions is too large")
	}
}

func (n *Node) requestMissingTransactions(ctx context.Context, hashes []hash.Hash) {
	txs := make([][]byte, 0, len(hashes))

	requestOp := func() error {
		if len(hashes) == 0 {
			return nil
		}

		rsp, err := n.txSync.GetTxs(ctx, &txsync.GetTxsRequest{
			Txs: hashes,
		})
		if err != nil {
			n.logger.Warn("failed to request missing transactions from peers",
				"err", err,
			)
			return err
		}

		n.logger.Debug("resolved (some) missing transactions",
			"resolved", len(rsp.Txs),
			"missing", len(hashes),
		)

		if len(rsp.Txs) == 0 {
			n.logger.Debug("no peer returned transactions",
				"hashes", hashes,
			)
		}

		txs = append(txs, rsp.Txs...)

		// Queue all transactions in the transaction pool.
		n.commonNode.TxPool.SubmitProposedBatch(rsp.Txs)

		// Check if there are still missing transactions, by reusing the slice.
		missing := hashes[:0]
		for _, hash := range hashes {
			if !n.commonNode.TxPool.Has(hash) {
				missing = append(missing, hash)
			}
		}
		hashes = missing

		if len(hashes) == 0 {
			return nil
		}

		// Perform another request.
		return fmt.Errorf("need to resolve more transactions")
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

	n.logger.Info("fetched all transactions needed for batch processing")

	select {
	case n.missingTxCh <- txs:
	case <-ctx.Done():
	}
}
