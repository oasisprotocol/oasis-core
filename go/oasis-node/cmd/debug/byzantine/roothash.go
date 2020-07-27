package byzantine

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

func roothashGetLatestBlock(ht *honestTendermint, height int64, runtimeID common.Namespace) (*block.Block, error) {
	return ht.service.RootHash().GetLatestBlock(context.Background(), runtimeID, height)
}

func roothashMergeCommit(svc consensus.Backend, id *identity.Identity, runtimeID common.Namespace, commits []commitment.MergeCommitment) error {
	tx := roothash.NewMergeCommitTx(0, nil, runtimeID, commits)
	return consensus.SignAndSubmitTx(context.Background(), svc, id.NodeSigner, tx)
}
