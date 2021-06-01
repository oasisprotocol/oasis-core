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

func roothashExecutorCommit(svc consensus.Backend, id *identity.Identity, runtimeID common.Namespace, commits []commitment.ExecutorCommitment) error {
	tx := roothash.NewExecutorCommitTx(0, nil, runtimeID, commits)
	return consensus.SignAndSubmitTx(context.Background(), svc, id.NodeSigner, tx)
}

func getRoothashLatestBlock(ctx context.Context, sbc consensus.Backend, runtimeID common.Namespace) (*block.Block, error) {
	return sbc.RootHash().GetLatestBlock(ctx, &roothash.RuntimeRequest{
		RuntimeID: runtimeID,
		Height:    consensus.HeightLatest,
	})
}
