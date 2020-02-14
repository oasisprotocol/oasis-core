// Package tests is a collection of worker test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	roothashTests "github.com/oasislabs/oasis-core/go/roothash/tests"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/worker/compute/txnscheduler"
	"github.com/oasislabs/oasis-core/go/worker/compute/txnscheduler/committee"
)

const recvTimeout = 5 * time.Second

// WorkerImplementationTests runs the worker implementation tests.
//
// NOTE: This test suite must be run before all other backend-specific
// suites as it requires that no epoch transitions have taken place
// after the node was registered.
func WorkerImplementationTests(
	t *testing.T,
	worker *txnscheduler.Worker,
	runtimeID common.Namespace,
	rtNode *committee.Node,
	epochtime epochtime.SetableBackend,
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
		testInitialEpochTransition(t, runtimeID, stateCh, epochtime, roothash)
	})

	t.Run("QueueCall", func(t *testing.T) {
		testQueueCall(t, runtimeID, stateCh, rtNode, roothash, storage)
	})

	// TODO: Add more tests.
}

func testInitialEpochTransition(
	t *testing.T,
	runtimeID common.Namespace,
	stateCh <-chan committee.NodeState,
	epochtime epochtime.SetableBackend,
	roothash roothash.Backend,
) {
	// Perform an epoch transition, so that the node gets elected leader.
	epoch := epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	// Ensure that the epoch transition block for the runtime ID we are
	// are using has been received by the roothash backend.
	roothashTests.MustTransitionEpoch(t, runtimeID, roothash, epochtime, epoch)

	// Node should transition to WaitingForBatch state.
	waitForNodeTransition(t, stateCh, committee.WaitingForBatch)
}

func testQueueCall(
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
	testCall := []byte("hello world")
	testEpochNumber := epochtime.EpochTime(2)
	err = rtNode.QueueCall(context.Background(), testEpochNumber, testCall)
	require.NoError(t, err, "QueueCall")

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
				Round:     blk.Header.Round,
				Hash:      blk.Header.IORoot,
			})
			defer tree.Close()

			txs, err := tree.GetTransactions(ctx)
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
