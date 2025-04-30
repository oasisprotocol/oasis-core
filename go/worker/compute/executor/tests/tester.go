// Package tests is a collection of worker test cases.
package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	commonCommittee "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor/committee"
)

const recvTimeout = 5 * time.Second

// WorkerImplementationTests runs the worker implementation tests.
//
// NOTE: This test suite must be run before all other backend-specific
// suites as it requires that no epoch transitions have taken place
// after the node was registered.
func WorkerImplementationTests(
	t *testing.T,
	worker *executor.Worker,
	runtimeID common.Namespace,
	commonNode *commonCommittee.Node,
	rtNode *committee.Node,
	backend consensus.Backend,
	storage storage.Backend,
) {
	// Wait for worker to start and register.
	<-worker.Initialized()

	// Subscribe to state transitions.
	stateCh, sub := rtNode.WatchStateTransitions()
	defer sub.Close()

	// Run the various test cases. (Ordering matters.)
	t.Run("InitialEpochTransition", func(t *testing.T) {
		testInitialEpochTransition(t, stateCh, backend)
	})

	t.Run("QueueTx", func(t *testing.T) {
		testQueueTx(t, runtimeID, stateCh, commonNode, rtNode, backend.RootHash(), storage)
	})

	// TODO: Add more tests.
}

func testInitialEpochTransition(t *testing.T, stateCh <-chan committee.NodeState, backend consensus.Backend) {
	// Perform an epoch transition, so that the node gets elected leader.
	beaconTests.MustAdvanceEpoch(t, backend)

	// Node should transition to WaitingForBatch state.
	waitForNodeTransition(t, stateCh, committee.WaitingForBatch)
}

func waitForNodeTransition(t *testing.T, stateCh <-chan committee.NodeState, expectedState committee.StateName) {
	timeout := time.After(recvTimeout)
	for {
		select {
		case newState := <-stateCh:
			if expectedState == newState.Name() {
				return
			}
		case <-timeout:
			t.Fatalf("failed to receive transition to %s state", expectedState)
			return
		}
	}
}

func testQueueTx(
	t *testing.T,
	runtimeID common.Namespace,
	stateCh <-chan committee.NodeState,
	commonNode *commonCommittee.Node,
	_ *committee.Node,
	roothash roothash.Backend,
	st storage.Backend,
) {
	ctx := context.Background()

	// Subscribe to roothash blocks.
	blocksCh, sub, err := roothash.WatchBlocks(ctx, runtimeID)
	require.NoError(t, err, "WatchBlocks")
	defer sub.Close()

	_, err = nextRuntimeBlock(blocksCh, true)
	require.NoError(t, err, "nextRuntimeBlock")

	// Include a timestamp so each test invocation uses a unique transaction.
	testTx := []byte("hello world at: " + time.Now().String())
	// Submit a test transaction.
	result, err := commonNode.TxPool.SubmitTx(ctx, testTx, &txpool.TransactionMeta{Local: false})
	require.NoError(t, err, "transaction should be accepted")
	require.True(t, result.IsSuccess(), "transaction should pass checks")

	// Node should transition to ProcessingBatch state.
	waitForNodeTransition(t, stateCh, committee.ProcessingBatch)

	// Node should transition to WaitingForBatch state and a block should be
	// finalized containing our batch.
	waitForNodeTransition(t, stateCh, committee.WaitingForBatch)

	// Fetch the first non-empty block.
	blk, err := nextRuntimeBlock(blocksCh, false)
	require.NoError(t, err, "failed to receive a block containing transaction")
	require.EqualValues(t, block.Normal, blk.Block.Header.HeaderType)

	// Check that correct block was generated.
	tree := transaction.NewTree(st, storage.Root{
		Namespace: blk.Block.Header.Namespace,
		Version:   blk.Block.Header.Round,
		Type:      storage.RootTypeIO,
		Hash:      blk.Block.Header.IORoot,
	})
	defer tree.Close()

	var txs []*transaction.Transaction
	txs, err = tree.GetTransactions(ctx)
	require.NoError(t, err, "GetTransactions")
	require.Len(t, txs, 1, "there should be one transaction")
	require.EqualValues(t, testTx, txs[0].Input)
	// NOTE: Mock host produces output equal to input.
	require.EqualValues(t, testTx, txs[0].Output)

	// NOTE: Mock host produces an empty state root.
	var stateRoot hash.Hash
	stateRoot.Empty()
	require.EqualValues(t, stateRoot, blk.Block.Header.StateRoot)

	// Submitting the same transaction should not result in a new block.
	_, err = commonNode.TxPool.SubmitTx(ctx, testTx, &txpool.TransactionMeta{Local: false})
	require.Error(t, err, "duplicate transaction should be rejected")

	// Fetch the first non-empty block.
	_, err = nextRuntimeBlock(blocksCh, true)
	require.Error(t, err, "unexpected block as a result of a duplicate transaction")
}

// nextRuntimeBlock return the next (non-empty) runtime block.
func nextRuntimeBlock(ch <-chan *roothash.AnnotatedBlock, allowEmpty bool) (*roothash.AnnotatedBlock, error) {
	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("runtime block channel closed")
			}
			if !allowEmpty && blk.Block.Header.IORoot.IsEmpty() {
				// Skip blocks without transactions.
				continue
			}
			return blk, nil
		case <-time.After(recvTimeout):
			return nil, fmt.Errorf("failed to receive runtime block")
		}
	}
}
