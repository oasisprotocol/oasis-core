// Package tests is a collection of worker test cases.
package tests

import (
	"testing"
	"time"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	"github.com/oasislabs/oasis-core/go/worker/compute/committee"
)

const recvTimeout = 5 * time.Second

// WorkerImplementationTests runs the worker implementation tests.
//
// NOTE: This test suite must be run before all other backend-specific
// suites as it requires that no epoch transitions have taken place
// after the node was registered.
func WorkerImplementationTests(
	t *testing.T,
	worker *compute.Worker,
	runtimeID signature.PublicKey,
	rtNode *committee.Node,
	epochtime epochtime.SetableBackend,
) {
	// Wait for worker to start and register.
	<-worker.Initialized()

	// Subscribe to state transitions.
	stateCh, sub := rtNode.WatchStateTransitions()
	defer sub.Close()

	// Run the various test cases. (Ordering matters.)
	t.Run("InitialEpochTransition", func(t *testing.T) {
		testInitialEpochTransition(t, stateCh, epochtime)
	})

	// TODO: Add more tests.
}

func testInitialEpochTransition(t *testing.T, stateCh <-chan committee.NodeState, epochtime epochtime.SetableBackend) {
	// Perform an epoch transition, so that the node gets elected leader.
	epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

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
