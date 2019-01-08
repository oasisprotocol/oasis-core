// Package tests is a collection of worker test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/runtime"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	registryApi "github.com/oasislabs/ekiden/go/registry/api"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/worker"
	"github.com/oasislabs/ekiden/go/worker/committee"
)

const recvTimeout = 5 * time.Second

// WorkerImplementationTests runs the worker implementation tests.
//
// NOTE: This test suite must be run before all other backend-specific
// suites as it requires that no epoch transitions have taken place
// after the node was registered.
func WorkerImplementationTests(
	t *testing.T,
	worker *worker.Worker,
	epochtime epochtime.SetableBackend,
	registry registryApi.Backend,
	roothash roothash.Backend,
	identity *identity.Identity,
) {
	// Get the runtime and the corresponding committee node instance.
	runtimeID := worker.GetConfig().Runtimes[0].ID
	rt := worker.GetRuntime(runtimeID)
	require.NotNil(t, rt)
	rtNode := rt.GetNode()

	// Wait for worker to start and register.
	<-worker.Initialized()

	// Ensure that we leave the registry empty when we are done.
	defer func() {
		// Stop the node and wait for it to fully stop. This is required
		// as otherwise the node will re-register itself on each epoch
		// transition.
		rtNode.Stop()
		<-rtNode.Quit()

		// Deregister the entity which should also deregister the node.
		ts := registryApi.Timestamp(uint64(time.Now().Unix()))
		signed, err := signature.SignSigned(*identity.NodeKey, registryApi.DeregisterEntitySignatureContext, &ts)
		require.NoError(t, err, "SignSigned")

		err = registry.DeregisterEntity(context.Background(), signed)
		require.NoError(t, err, "DeregisterEntity")

		registryTests.EnsureRegistryEmpty(t, registry)
	}()

	// Subscribe to state transitions.
	stateCh, sub := rtNode.WatchStateTransitions()
	defer sub.Close()

	// Run the various test cases. (Ordering matters.)
	t.Run("InitialEpochTransition", func(t *testing.T) {
		testInitialEpochTransition(t, stateCh, epochtime)
	})

	t.Run("QueueCall", func(t *testing.T) {
		testQueueCall(t, runtimeID, stateCh, rtNode, roothash)
	})

	// TODO: Add more tests.
}

func testInitialEpochTransition(t *testing.T, stateCh <-chan committee.NodeState, epochtime epochtime.SetableBackend) {
	// Perform an epoch transition, so that the node gets elected leader.
	epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	// Node should transition to WaitingForBatch state.
	waitForNodeTransition(t, stateCh, "WaitingForBatch")
}

func testQueueCall(
	t *testing.T,
	runtimeID signature.PublicKey,
	stateCh <-chan committee.NodeState,
	rtNode *committee.Node,
	roothash roothash.Backend,
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
	err = rtNode.QueueCall(context.Background(), testCall)
	require.NoError(t, err, "QueueCall")

	// Node should transition to ProcessingBatch state.
	waitForNodeTransition(t, stateCh, "ProcessingBatch")

	// Node should transition to WaitingForFinalize state.
	waitForNodeTransition(t, stateCh, "WaitingForFinalize")

	// Node should transition to WaitingForBatch state and a block should be
	// finalized containing our batch.
	waitForNodeTransition(t, stateCh, "WaitingForBatch")

	select {
	case blk := <-blocksCh:
		// Check that correct block was generated.
		var batchHash hash.Hash
		batch := runtime.Batch([][]byte{testCall})
		batchHash.From(batch)

		require.EqualValues(t, block.Normal, blk.Header.HeaderType)
		require.EqualValues(t, batchHash, blk.Header.InputHash)
		// NOTE: Mock host produces output equal to input.
		require.EqualValues(t, batchHash, blk.Header.OutputHash)
		// NOTE: Mock host produces state root equal to input.
		require.EqualValues(t, batchHash, blk.Header.StateRoot)
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive block")
	}
}

func waitForNodeTransition(t *testing.T, stateCh <-chan committee.NodeState, expectedState string) {
	select {
	case newState := <-stateCh:
		require.EqualValues(t, expectedState, newState.String())
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive transition to %s state", expectedState)
	}
}
