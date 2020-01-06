package byzantine

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/identity"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
)

func roothashGetLatestBlock(ht *honestTendermint, height int64, runtimeID common.Namespace) (*block.Block, error) {
	return ht.service.RootHash().GetLatestBlock(context.Background(), runtimeID, height)
}

func roothashMergeCommit(svc service.TendermintService, id *identity.Identity, runtimeID common.Namespace, commits []commitment.MergeCommitment) error {
	tx := roothash.NewMergeCommitTx(0, nil, runtimeID, commits)
	return consensus.SignAndSubmitTx(context.Background(), svc, id.NodeSigner, tx)
}
