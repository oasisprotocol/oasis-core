package committee

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
)

// unresolvedBatch is a batch that may still need to be resolved (fetched from storage).
type unresolvedBatch struct {
	proposal *commitment.Proposal

	batch       transaction.RawBatch
	missingTxs  map[hash.Hash]int
	resolvedTxs map[hash.Hash][]byte

	maxBatchSizeBytes uint64
}

func (ub *unresolvedBatch) String() string {
	switch {
	case ub.proposal != nil:
		return fmt.Sprintf("UnresolvedBatch{hash: %s}", ub.proposal.Header.BatchHash)
	default:
		return "UnresolvedBatch{?}"
	}
}

func (ub *unresolvedBatch) hash() hash.Hash {
	if ub.proposal == nil {
		return hash.Hash{}
	}
	return ub.proposal.Header.BatchHash
}

func (ub *unresolvedBatch) addResolvedTx(tx []byte) {
	if ub.missingTxs == nil {
		return
	}

	txHash := hash.NewFromBytes(tx)
	if _, exists := ub.missingTxs[txHash]; !exists {
		return
	}

	if ub.resolvedTxs == nil {
		ub.resolvedTxs = make(map[hash.Hash][]byte)
	}
	ub.resolvedTxs[txHash] = tx
	delete(ub.missingTxs, txHash)
}

func (ub *unresolvedBatch) resolve(txPool txpool.TransactionPool) (transaction.RawBatch, error) {
	if ub.batch != nil {
		return ub.batch, nil
	}
	if ub.proposal == nil {
		return nil, fmt.Errorf("resolve called on unresolvable batch")
	}
	if len(ub.proposal.Batch) == 0 {
		return transaction.RawBatch{}, nil
	}

	resolvedBatch, missingTxs := txPool.GetKnownBatch(ub.proposal.Batch)
	if ub.resolvedTxs != nil {
		for txHash, txIdx := range missingTxs {
			rawTx, exists := ub.resolvedTxs[txHash]
			if !exists {
				continue
			}

			delete(missingTxs, txHash)
			resolvedBatch[txIdx] = transaction.RawCheckedTransaction(rawTx)
		}
	}
	if len(missingTxs) > 0 {
		ub.missingTxs = missingTxs
		return nil, nil
	}
	ub.missingTxs = nil

	var (
		batch          transaction.RawBatch
		totalSizeBytes uint64
	)
	for _, checkedTx := range resolvedBatch {
		totalSizeBytes = totalSizeBytes + checkedTx.Size()
		if ub.maxBatchSizeBytes > 0 && totalSizeBytes > ub.maxBatchSizeBytes {
			return nil, fmt.Errorf("batch too large (max: %d size: >=%d)", ub.maxBatchSizeBytes, totalSizeBytes)
		}
		// TODO: Also check against weight limits.

		batch = append(batch, checkedTx.Raw())
	}
	ub.batch = batch

	return batch, nil
}
