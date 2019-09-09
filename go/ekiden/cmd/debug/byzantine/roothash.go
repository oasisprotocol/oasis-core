package byzantine

import (
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	roothashapp "github.com/oasislabs/ekiden/go/tendermint/apps/roothash"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

func roothashGetLatestBlock(svc service.TendermintService, height int64, runtimeID signature.PublicKey) (*block.Block, error) {
	response, err := svc.Query(roothashapp.QueryGetLatestBlock, tmapi.QueryGetByIDRequest{
		ID: runtimeID,
	}, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "Tendermint Query %s", roothashapp.QueryGetLatestBlock)
	}

	var block block.Block
	if err := cbor.Unmarshal(response, &block); err != nil {
		return nil, errors.Wrap(err, "CBOR Unmarshal block")
	}

	return &block, nil
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
