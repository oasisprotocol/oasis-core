// Package tests is a collection of consensus implementation test cases.
package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	epochtimemock "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/epochtime_mock"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
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

	genDoc, err := backend.GetGenesisDocument(ctx)
	require.NoError(err, "GetGenesisDocument")
	require.NotNil(genDoc, "returned genesis document should not be nil")

	blk, err := backend.GetBlock(ctx, consensus.HeightLatest)
	require.NoError(err, "GetBlock")
	require.NotNil(blk, "returned block should not be nil")
	require.True(blk.Height > 0, "block height should be greater than zero")

	status, err := backend.GetStatus(ctx)
	require.NoError(err, "GetStatus")
	require.NotNil(status, "returned status should not be nil")
	require.EqualValues(1, status.GenesisHeight, "genesis height must be 1")

	blk, err = backend.GetBlock(ctx, status.LatestHeight)
	require.NoError(err, "GetBlock")

	require.EqualValues(blk.Height, status.LatestHeight, "latest block heights should match")
	require.EqualValues(blk.Hash, status.LatestHash, "latest block hashes should match")
	require.EqualValues(blk.StateRoot, status.LatestStateRoot, "latest state roots should match")

	txs, err := backend.GetTransactions(ctx, consensus.HeightLatest)
	require.NoError(err, "GetTransactions")

	txsWithResults, err := backend.GetTransactionsWithResults(ctx, consensus.HeightLatest)
	require.NoError(err, "GetTransactionsWithResults")
	require.Len(
		txsWithResults.Transactions,
		len(txs),
		"GetTransactionsWithResults.Transactions length missmatch",
	)
	require.Len(
		txsWithResults.Results,
		len(txsWithResults.Transactions),
		"GetTransactionsWithResults.Results length missmatch",
	)

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
		Signer:      memorySigner.NewTestSigner("estimate gas signer").Public(),
		Transaction: transaction.NewTransaction(0, nil, epochtimemock.MethodSetEpoch, 0),
	})
	require.NoError(err, "EstimateGas")

	nonce, err := backend.GetSignerNonce(ctx, &consensus.GetSignerNonceRequest{
		AccountAddress: staking.NewAddress(
			signature.NewPublicKey("badfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		),
		Height: consensus.HeightLatest,
	})
	require.NoError(err, "GetSignerNonce")
	require.Equal(uint64(0), nonce, "Nonce should be zero")

	// Light client API.
	shdr, err := backend.GetSignedHeader(ctx, blk.Height)
	require.NoError(err, "GetSignedHeader")
	require.Equal(shdr.Height, blk.Height, "returned header height should be correct")
	require.NotNil(shdr.Meta, "returned header should contain metadata")

	vals, err := backend.GetValidatorSet(ctx, blk.Height)
	require.NoError(err, "GetValidatorSet")
	require.Equal(vals.Height, blk.Height, "returned validator set height should be correct")
	require.NotNil(vals.Meta, "returned validator set should contain metadata")

	params, err := backend.GetParameters(ctx, blk.Height)
	require.NoError(err, "GetParameters")
	require.Equal(params.Height, blk.Height, "returned parameters height should be correct")
	require.NotNil(params.Meta, "returned parameters should contain metadata")

	err = backend.SubmitTxNoWait(ctx, &transaction.SignedTransaction{})
	require.Error(err, "SubmitTxNoWait should fail with invalid transaction")

	testTx := transaction.NewTransaction(0, nil, epochtimemock.MethodSetEpoch, epoch)
	testSigner := memorySigner.NewTestSigner(fmt.Sprintf("consensus tests tx signer: %T", backend))
	testSigTx, err := transaction.Sign(testSigner, testTx)
	require.NoError(err, "transaction.Sign")
	err = backend.SubmitTxNoWait(ctx, testSigTx)
	require.NoError(err, "SubmitTxNoWait")

	err = backend.SubmitEvidence(ctx, &consensus.Evidence{})
	require.Error(err, "SubmitEvidence should fail with invalid evidence")

	// We should be able to do remote state queries. Of course the state format is backend-specific
	// so we simply perform some usual storage operations like fetching random keys and iterating
	// through everything.
	state := mkvs.NewWithRoot(backend.State(), nil, blk.StateRoot)
	defer state.Close()

	it := state.NewIterator(ctx)
	defer it.Close()

	var keys [][]byte
	for it.Rewind(); it.Valid(); it.Next() {
		keys = append(keys, it.Key())
	}
	require.NoError(it.Err(), "iterator should not return an error")
	require.NotEmpty(keys, "there should be some keys in consensus state")

	// Start with a clean tree to avoid hitting the cache.
	state = mkvs.NewWithRoot(backend.State(), nil, blk.StateRoot)
	defer state.Close()

	for _, key := range keys {
		_, err = state.Get(ctx, key)
		require.NoError(err, "state.Get(%X)", key)
	}

	// Start with a clean tree to avoid hitting the cache.
	state = mkvs.NewWithRoot(backend.State(), nil, blk.StateRoot)
	defer state.Close()

	err = state.PrefetchPrefixes(ctx, keys[:1], 10)
	require.NoError(err, "state.PrefetchPrefixes")
}
