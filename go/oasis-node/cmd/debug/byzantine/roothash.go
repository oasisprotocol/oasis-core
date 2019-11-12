package byzantine

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	roothashapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/roothash"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
)

func roothashGetLatestBlock(ht *honestTendermint, height int64, runtimeID signature.PublicKey) (*block.Block, error) {
	return ht.service.RootHash().GetLatestBlock(context.Background(), runtimeID, height)
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
