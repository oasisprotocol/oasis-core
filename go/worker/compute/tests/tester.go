// Package tests is a collection of worker test cases.
package tests

import (
	"testing"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	ticker "github.com/oasislabs/ekiden/go/ticker/api"
	tickerTests "github.com/oasislabs/ekiden/go/ticker/tests"
	"github.com/oasislabs/ekiden/go/worker/compute"
	"github.com/oasislabs/ekiden/go/worker/compute/committee"
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
	timeSource ticker.SetableBackend,
	scheduler scheduler.Backend,
) {
	// Wait for worker to start and register.
	<-worker.Initialized()

	// Subscribe to state transitions.
	stateCh, sub := rtNode.WatchStateTransitions()
	defer sub.Close()

	// Run the various test cases. (Ordering matters.)
	t.Run("InitialEpochTransition", func(t *testing.T) {
		testInitialEpochTransition(t, stateCh, timeSource, scheduler)
	})

	// TODO: Add more tests.
}

func testInitialEpochTransition(t *testing.T, stateCh <-chan committee.NodeState, timeSource ticker.SetableBackend, scheduler scheduler.Backend) {
	// Perform an epoch transition, so that the node gets elected leader.
	tickerTests.MustAdvanceEpoch(t, timeSource, scheduler)

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
