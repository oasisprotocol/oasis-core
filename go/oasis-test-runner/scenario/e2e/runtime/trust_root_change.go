package runtime

import (
	"context"
	"fmt"
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
)

const (
	// LogEventTrustRootChangeNoTrust is the event emitted when a compute
	// worker fails to initialize the verifier as there is not enough trust
	// in the new light block.
	LogEventTrustRootChangeNoTrust = "consensus/tendermint/verifier/chain_context/no_trust"

	// LogEventTrustRootChangeFailed is the event emitted when a compute
	// worker fails to initialize the verifier as the new light block is
	// invalid, e.g. has lower height than the last known trusted block.
	LogEventTrustRootChangeFailed = "consensus/tendermint/verifier/chain_context/failed"
)

var (
	// TrustRootChangeTest is a happy path scenario which tests if trust
	// can be transferred to a new light block when consensus chain context
	// changes, e.g. on dump-restore network upgrades.
	TrustRootChangeTest scenario.Scenario = newTrustRootChangeImpl("change", NewLongTermTestClient().WithMode(ModePart1NoMsg), true)

	// TrustRootChangeFailsTest is an unhappy path scenario which tests
	// that trust is never transferred to untrusted or invalid light blocks when
	// consensus chain context changes.
	TrustRootChangeFailsTest scenario.Scenario = newTrustRootChangeImpl("change-fails", BasicKVTestClient, false)
)

type trustRootChangeImpl struct {
	trustRootImpl

	// Happy or unhappy scenario.
	happy bool
}

func newTrustRootChangeImpl(name string, testClient TestClient, happy bool) *trustRootChangeImpl {
	// We will use 3 validators inherited from trust root scenario fixture
	// to test what happens if the new validator set doesn't have enough
	// voting power after chain context changes. Since all validators have
	// the same voting power we can remove one of them and the rest will have
	// only 2/3 of the votes, just a bit too shy.
	//
	// For happy path we use a long-term test client as it enables us to test
	// if the key/value store remains intact after multiple chain context
	// changes.
	sc := &trustRootChangeImpl{
		trustRootImpl: *newTrustRootImpl(name, testClient),
		happy:         happy,
	}

	return sc
}

func (sc *trustRootChangeImpl) Clone() scenario.Scenario {
	return &trustRootChangeImpl{
		trustRootImpl: *sc.trustRootImpl.Clone().(*trustRootImpl),
		happy:         sc.happy,
	}
}

func (sc *trustRootChangeImpl) Run(childEnv *env.Env) error {
	if !sc.happy {
		return sc.unhappyRun(childEnv)
	}
	return sc.happyRun(childEnv)
}

// happyRun tests that trust is transferred to a new light block when consensus
// chain context changes if validator set has enough votes.
//
// It consists of 3 steps:
//   - Build a simple key/value runtime with an embedded trust root, register
//     it to the network together with key manager runtime and test that
//     everything works.
//   - Do dump/restore procedure which simulates a real network upgrade.
//     This step will stop the network, clear everything except runtime's
//     local storage (we need it as the verifier has last trust root
//     stored in it) and change consensus chain context. The latter will
//     force the verifier to check if transition to a new light block
//     is possible.
//   - Start the network and test if everything works.
//   - Repeat last two points. Chain context transition can be done repeatedly,
//     as long as new light blocks are trusted and valid.
func (sc *trustRootChangeImpl) happyRun(childEnv *env.Env) (err error) {
	ctx := context.Background()

	// Step 1: Build a simple key/value runtime and start the network.
	rebuild, err := sc.buildKeyValueRuntime(ctx, childEnv)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := rebuild(); err2 != nil {
			err = fmt.Errorf("%w (original error: %s)", err2, err)
		}
	}()

	// All chain contexts should be unique.
	chainContexts := make(map[string]struct{})
	c, err := sc.chainContext(ctx)
	if err != nil {
		return err
	}
	chainContexts[c] = struct{}{}

	for round := int64(1); round <= 2; round++ {
		// Step 2: Dump/restore network.
		if err = sc.dumpRestoreNetwork(childEnv, nil, nil); err != nil {
			return err
		}

		// Step 3: Start the network and test if everything works.
		if err = sc.Net.Start(); err != nil {
			return err
		}

		// Assert that chain context has changed. Test is meaningless if this
		// doesn't happen.
		c, err = sc.chainContext(ctx)
		if err != nil {
			return err
		}
		if _, ok := chainContexts[c]; ok {
			return fmt.Errorf("chain context hasn't changed")
		}
		chainContexts[c] = struct{}{}

		// Test runtime to be sure that blocks get processed correctly.
		// We do this by checking if key/value store was successfully restored.
		if err := sc.startClientAndComputeWorkers(ctx, childEnv); err != nil {
			return err
		}
		if err := sc.startRestoredStateTestClient(ctx, childEnv, round); err != nil {
			return err
		}
	}

	// Check logs whether any issues were detected.
	if err := sc.Net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}

// unhappyRun tests that trust is never transferred to untrusted or invalid
// light blocks when consensus chain context changes.
//
// It consists of 5 steps:
//   - Build a simple key/value runtime with an embedded trust root, register
//     it to the network together with key manager runtime and test that
//     everything works.
//   - Stop the network, set genesis height to 1 and reset the consensus state.
//     This will cause a chain context change when the network will be started
//     again. When doing state wipe be careful not to delete compute workers
//     local storages as they contain sealed trusted roots.
//   - Start the network. If everything works as expected, compute workers
//     should never be ready as the verifier cannot transfer trust to light
//     blocks on a new chain.
//   - Repeat last two points. This time set genesis height to something big
//     and remove one validator from the set so that we can simulate what
//     happens when the new validator set has only 2/3 of the voting power.
func (sc *trustRootChangeImpl) unhappyRun(childEnv *env.Env) (err error) {
	ctx := context.Background()

	// Step 1: Build a simple key/value runtime and start the network.
	rebuild, err := sc.buildKeyValueRuntime(ctx, childEnv)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := rebuild(); err2 != nil {
			err = fmt.Errorf("%w (original error: %s)", err2, err)
		}
	}()

	chainContext, err := sc.chainContext(ctx)
	if err != nil {
		return err
	}

	// Prepare functions for dump/restore procedures.
	nodeID := sc.Net.Validators()[2].NodeID // Selected for removal in step 4.

	f := []func(fixture *oasis.NetworkFixture){
		// First dump with too low genesis height.
		func(fixture *oasis.NetworkFixture) {
			// Make sure all nodes are started initially although we only need
			// one compute worker. We have to start them as otherwise tendermint
			// reset will fail.
			for i := range fixture.ComputeWorkers {
				fixture.ComputeWorkers[i].NoAutoStart = false
			}
			for i := range fixture.Clients {
				fixture.Clients[i].NoAutoStart = false
			}

			// Observe logs for invalid genesis block error messages.
			fixture.ComputeWorkers[0].LogWatcherHandlerFactories = []log.WatcherHandlerFactory{
				oasis.LogAssertEvent(LogEventTrustRootChangeFailed, "the verifier should emit invalid genesis block event"),
			}
		},

		// Second dump without one validator.
		func(fixture *oasis.NetworkFixture) {
			// Remove one validator in the set so that trust validation will
			// fail and observe logs for failure.
			fixture.Validators = fixture.Validators[:2]
			fixture.ComputeWorkers[0].NoAutoStart = false
			fixture.ComputeWorkers[0].LogWatcherHandlerFactories = []log.WatcherHandlerFactory{
				oasis.LogAssertEvent(LogEventTrustRootChangeNoTrust, "the verifier should emit not trusted chain event"),
			}
		},
	}

	g := []func(doc *genesis.Document){
		// First dump with too low genesis height.
		func(doc *genesis.Document) {
			// Reset height to get an invalid genesis block error message.
			doc.Height = 1
		},

		// Second dump without one validator.
		func(doc *genesis.Document) {
			// Remove one validator from the genesis. Since the order
			// of validators in fixture and genesis may not be the same,
			// be careful to remove the right one.
			nodes := make([]*node.MultiSignedNode, 0, 2)
			for _, n := range doc.Registry.Nodes {
				if n.Signatures[0].PublicKey != nodeID {
					nodes = append(nodes, n)
				}
			}
			doc.Registry.Nodes = nodes

			// Remove status also.
			delete(doc.Registry.NodeStatuses, nodeID)

			// Height should be larger than the height of the latest trust root.
			doc.Height = 1000
		},
	}

	for i := 0; i < 2; i++ {
		// Step 2,4: Dump/restore network.
		if err = sc.dumpRestoreNetwork(childEnv, f[i], g[i]); err != nil {
			return err
		}

		// Step 3,5: Start the network and verify compute workers.
		if err = sc.Net.Start(); err != nil {
			return err
		}
		if err = sc.Net.Controller().WaitNodesRegistered(ctx, len(sc.Net.Validators())); err != nil {
			return err
		}

		// Assert that chain context has changed. Test is meaningless if this
		// doesn't happen.
		newChainContext, err := sc.chainContext(ctx)
		if err != nil {
			return err
		}
		if newChainContext == chainContext {
			return fmt.Errorf("chain context hasn't changed")
		}

		// Running network for few blocks so that compute workers have enough
		// time to get ready.
		_, err = sc.waitBlocks(ctx, 25)
		if err != nil {
			return err
		}

		// Starting the key/value runtime should now be a problem for compute
		// workers as the verifier will never initialize.
		if err := sc.Net.CheckLogWatchers(); err != nil {
			return err
		}
	}

	return nil
}

func (sc *trustRootChangeImpl) buildKeyValueRuntime(ctx context.Context, childEnv *env.Env) (func() error, error) {
	// Start network with validators only, as configured in the fixture.
	// We need those to produce blocks from which we pick one and use it
	// as our embedded trust root.
	if err := sc.Net.Start(); err != nil {
		return nil, err
	}
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, len(sc.Net.Validators())); err != nil {
		return nil, err
	}

	// Pick one block and use it as an embedded trust root.
	block, err := sc.waitBlocks(ctx, 3)
	if err != nil {
		return nil, err
	}
	chainContext, err := sc.chainContext(ctx)
	if err != nil {
		return nil, err
	}
	root := trustRoot{
		height:       strconv.FormatInt(block.Height, 10),
		hash:         block.Hash.Hex(),
		runtimeID:    runtimeID.String(),
		chainContext: chainContext,
	}

	// Build the runtime using given trust root. Observe that we are changing
	// the binary here, so we need to rebuild the runtime when we are done.
	rebuild, err := sc.buildRuntimeBinary(ctx, childEnv, root)
	if err != nil {
		return nil, err
	}

	// Once binary with the embedded root is built, we can register runtimes.
	if err = sc.registerRuntimes(ctx, childEnv); err != nil {
		return nil, err
	}

	// Test runtime to be sure that blocks get processed correctly.
	// Remember that only validators are currently running.
	if err = sc.startClientAndComputeWorkers(ctx, childEnv); err != nil {
		return nil, err
	}

	// Test transactions.
	if err := sc.startTestClientOnly(ctx, childEnv); err != nil {
		return nil, err
	}
	if err := sc.waitTestClient(); err != nil {
		return nil, err
	}

	return rebuild, nil
}

func (sc *trustRootChangeImpl) dumpRestoreNetwork(childEnv *env.Env, f func(*oasis.NetworkFixture), g func(*genesis.Document)) error {
	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Apply changes to the fixture.
	if f != nil {
		f(fixture)
	}

	// Don't delete trust root.
	resetFlags := map[uint8]bool{
		e2e.PreserveComputeWorkerLocalStorage:   true,
		e2e.PreserveComputeWorkerRuntimeStorage: true, // default, needed
		e2e.PreserveKeymanagerLocalStorage:      true, // default, needed
	}
	if err = sc.DumpRestoreNetwork(childEnv, fixture, false, g, resetFlags); err != nil {
		return err
	}

	return nil
}

func (sc *trustRootChangeImpl) startClientAndComputeWorkers(ctx context.Context, childEnv *env.Env) error {
	// Start client and compute workers as they are not auto started.
	sc.Logger.Info("starting clients and compute workers")
	for _, n := range sc.Net.Clients() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}
	for _, n := range sc.Net.ComputeWorkers() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}
	sc.Logger.Info("waiting for compute workers to become ready")
	for _, n := range sc.Net.ComputeWorkers() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Setup a client controller as there is none due to the client node not
	// being auto started.
	ctrl, err := oasis.NewController(sc.Net.Clients()[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create client controller: %w", err)
	}
	sc.Net.SetClientController(ctrl)

	return nil
}

func (sc *trustRootChangeImpl) startRestoredStateTestClient(ctx context.Context, childEnv *env.Env, round int64) error {
	// Check that everything works with restored state.
	seed := fmt.Sprintf("seed %d", round)
	newTestClient := sc.testClient.Clone().(*LongTermTestClient)
	sc.runtimeImpl.testClient = newTestClient.WithMode(ModePart2).WithSeed(seed)
	if err := sc.runtimeImpl.Run(childEnv); err != nil {
		return err
	}
	return nil
}
