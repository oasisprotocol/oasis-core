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

	batch      transaction.RawBatch
	missingTxs map[hash.Hash]int

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
	if len(missingTxs) > 0 {
		ub.missingTxs = missingTxs
		return nil, nil
	}
	ub.missingTxs = nil

	var (
		batch          transaction.RawBatch
		totalSizeBytes int
	)
	for _, checkedTx := range resolvedBatch {
		totalSizeBytes = totalSizeBytes + checkedTx.Size()
		if ub.maxBatchSizeBytes > 0 && uint64(totalSizeBytes) > ub.maxBatchSizeBytes {
			return nil, fmt.Errorf("batch too large (max: %d size: >=%d)", ub.maxBatchSizeBytes, totalSizeBytes)
		}

		batch = append(batch, checkedTx.Raw())
	}
	ub.batch = batch

	return batch, nil
}
