package byzantine

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	roothashapp "github.com/oasislabs/oasis-core/go/tendermint/apps/roothash"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

func roothashGetLatestBlock(ht *honestTendermint, height int64, runtimeID signature.PublicKey) (*block.Block, error) {
	q, err := ht.roothashQuery.QueryAt(context.Background(), height)
	if err != nil {
		return nil, err
	}

	return q.LatestBlock(context.Background(), runtimeID)
}

func roothashMergeCommit(svc service.TendermintService, runtimeID signature.PublicKey, commits []commitment.MergeCommitment) error {
	if err := tendermintBroadcastTxCommit(svc, roothashapp.TransactionTag, roothashapp.Tx{
		TxMergeCommit: &roothashapp.TxMergeCommit{
			ID:      runtimeID,
			Commits: commits,
		},
	}); err != nil {
		return errors.Wrap(err, "Tendermint BroadcastTx commit")
	}

	return nil
}
