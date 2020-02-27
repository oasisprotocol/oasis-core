// Package tests is a collection of consensus implementation test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/epochtime_mock"
)

const (
	recvTimeout = 5 * time.Second

	numWaitedBlocks = 3
)

// ConsensusImplementationTests exercises the basic functionality of a
// consensus backend.
func ConsensusImplementationTests(t *testing.T, backend consensus.ClientBackend) {
	require := require.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	blk, err := backend.GetBlock(ctx, consensus.HeightLatest)
	require.NoError(err, "GetBlock")
	require.NotNil(blk, "returned block should not be nil")
	require.True(blk.Height > 0, "block height should be greater than zero")

	_, err = backend.GetTransactions(ctx, consensus.HeightLatest)
	require.NoError(err, "GetTransactions")

	blockCh, blockSub, err := backend.WatchBlocks(ctx)
	require.NoError(err, "WatchBlocks")
	defer blockSub.Close()

	// Wait for a few blocks.
	for i := 0; i < numWaitedBlocks; i++ {
		select {
		case newBlk := <-blockCh:
			require.NotNil(newBlk, "returned block should not be nil")
			require.True(newBlk.Height > blk.Height, "block height should be greater than previous")
			blk = newBlk
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive consensus block")
		}
	}

	epoch, err := backend.GetEpoch(ctx, consensus.HeightLatest)
	require.NoError(err, "GetEpoch")
	require.True(epoch > 0, "epoch height should be greater than zero")

	_, err = backend.EstimateGas(ctx, &consensus.EstimateGasRequest{
		Caller:      memorySigner.NewTestSigner("estimate gas signer").Public(),
		Transaction: transaction.NewTransaction(0, nil, epochtimemock.MethodSetEpoch, 0),
	})
	require.NoError(err, "EstimateGas")

	nonce, err := backend.GetSignerNonce(ctx, &consensus.GetSignerNonceRequest{
		ID:     memorySigner.NewTestSigner("get signer nonce signer").Public(),
		Height: consensus.HeightLatest,
	})
	require.NoError(err, "GetSignerNonce")
	require.Equal(uint64(0), nonce, "Nonce should be zero")
}
