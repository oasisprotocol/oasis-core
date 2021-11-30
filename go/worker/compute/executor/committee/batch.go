package committee

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	schedulingAPI "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

// unresolvedBatch is a batch that may still need to be resolved (fetched from storage).
type unresolvedBatch struct {
	proposal *commitment.Proposal

	batch      transaction.RawBatch
	missingTxs map[hash.Hash]int

	maxBatchSizeBytes uint64
}

func (ub *unresolvedBatch) String() string {
	return fmt.Sprintf("UnresolvedBatch{hash: %s}", ub.proposal.Header.BatchHash)
}

func (ub *unresolvedBatch) hash() hash.Hash {
	return ub.proposal.Header.BatchHash
}

func (ub *unresolvedBatch) resolve(scheduler schedulingAPI.Scheduler) (transaction.RawBatch, error) {
	if ub.batch != nil {
		return ub.batch, nil
	}
	if len(ub.proposal.Batch) == 0 {
		return transaction.RawBatch{}, nil
	}

	resolvedBatch, missingTxs := scheduler.GetKnownBatch(ub.proposal.Batch)
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
