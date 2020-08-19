// Package tests is a collection of worker test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
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
	rtNode *committee.Node,
	beacon beacon.SetableBackend,
	roothash roothash.Backend,
	storage storage.Backend,
) {
	// Wait for worker to start and register.
	<-worker.Initialized()

	// Subscribe to state transitions.
	stateCh, sub := rtNode.WatchStateTransitions()
	defer sub.Close()

	// Run the various test cases. (Ordering matters.)
	t.Run("InitialEpochTransition", func(t *testing.T) {
		testInitialEpochTransition(t, stateCh, beacon)
	})

	t.Run("QueueTx", func(t *testing.T) {
		testQueueTx(t, runtimeID, stateCh, rtNode, roothash, storage)
	})

	// TODO: Add more tests.
}

func testInitialEpochTransition(t *testing.T, stateCh <-chan committee.NodeState, beacon beacon.SetableBackend) {
	// Perform an epoch transition, so that the node gets elected leader.
	beaconTests.MustAdvanceEpoch(t, beacon, 1)

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
	rtNode *committee.Node,
	roothash roothash.Backend,
	st storage.Backend,
) {
	// Subscribe to roothash blocks.
	blocksCh, sub, err := roothash.WatchBlocks(runtimeID)
	require.NoError(t, err, "WatchBlocks")
	defer sub.Close()

	select {
	case <-blocksCh:
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive block")
	}

	// Queue a test call.
	// Include a timestamp so each test invocation uses an unique key.
	testCall := []byte("hello world at: " + time.Now().String())
	err = rtNode.QueueTx(testCall)
	require.NoError(t, err, "QueueCall")

	// Node should transition to ProcessingBatch state.
	waitForNodeTransition(t, stateCh, committee.ProcessingBatch)

	// Node should transition to WaitingForFinalize state.
	waitForNodeTransition(t, stateCh, committee.WaitingForFinalize)

	// Node should transition to WaitingForBatch state and a block should be
	// finalized containing our batch.
	waitForNodeTransition(t, stateCh, committee.WaitingForBatch)

blockLoop:
	for {
		select {
		case annBlk := <-blocksCh:
			blk := annBlk.Block

			// Check that correct block was generated.
			require.EqualValues(t, block.Normal, blk.Header.HeaderType)

			ctx := context.Background()
			tree := transaction.NewTree(st, storage.Root{
				Namespace: blk.Header.Namespace,
				Version:   blk.Header.Round,
				Hash:      blk.Header.IORoot,
			})
			defer tree.Close()

			var txs []*transaction.Transaction
			txs, err = tree.GetTransactions(ctx)
			require.NoError(t, err, "GetTransactions")
			require.Len(t, txs, 1, "there should be one transaction")
			require.EqualValues(t, testCall, txs[0].Input)
			// NOTE: Mock host produces output equal to input.
			require.EqualValues(t, testCall, txs[0].Output)

			// NOTE: Mock host produces an empty state root.
			var stateRoot hash.Hash
			stateRoot.Empty()
			require.EqualValues(t, stateRoot, blk.Header.StateRoot)
			break blockLoop
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive block")
		}
	}

	// Requeuing same call should fail.
	err = rtNode.QueueTx(testCall)
	require.Error(t, err, "QueueCall duplicate transaction")
}
