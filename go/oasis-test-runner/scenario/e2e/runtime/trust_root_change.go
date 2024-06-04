package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common/api"
)

// Keep the following two constants synced with the Rust part of the code in:
// runtime/src/consensus/tendermint/verifier/mod.rs.
const (
	// LogEventTrustRootChangeNoTrust is the event emitted when a compute
	// worker or a key manager node fails to initialize the verifier as there
	// is not enough trust in the new light block.
	LogEventTrustRootChangeNoTrust = "consensus/cometbft/verifier/chain_context/no_trust"

	// LogEventTrustRootChangeFailed is the event emitted when a compute
	// worker or a key manager node fails to initialize the verifier as
	// the new light block is invalid, e.g. has lower height than the last
	// known trusted block.
	LogEventTrustRootChangeFailed = "consensus/cometbft/verifier/chain_context/failed"
)

var (
	// TrustRootChangeTest is a happy path scenario which tests if trust
	// can be transferred to a new light block when consensus chain context
	// changes, e.g. on dump-restore network upgrades.
	TrustRootChangeTest scenario.Scenario = newTrustRootChangeImpl(
		"change",
		NewTestClient().WithScenario(InsertEncWithSecretsScenario),
		true,
	)

	// TrustRootChangeFailsTest is an unhappy path scenario which tests
	// that trust is never transferred to untrusted or invalid light blocks when
	// consensus chain context changes.
	TrustRootChangeFailsTest scenario.Scenario = newTrustRootChangeImpl(
		"change-fails",
		NewTestClient().WithScenario(SimpleEncWithSecretsScenario),
		false,
	)
)

type trustRootChangeImpl struct {
	TrustRootImpl

	// Happy or unhappy scenario.
	happy bool
}

func newTrustRootChangeImpl(name string, testClient *TestClient, happy bool) *trustRootChangeImpl {
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
		TrustRootImpl: *NewTrustRootImpl(name, testClient),
		happy:         happy,
	}

	return sc
}

func (sc *trustRootChangeImpl) Clone() scenario.Scenario {
	return &trustRootChangeImpl{
		TrustRootImpl: *sc.TrustRootImpl.Clone().(*TrustRootImpl),
		happy:         sc.happy,
	}
}

func (sc *trustRootChangeImpl) Run(ctx context.Context, childEnv *env.Env) error {
	if !sc.happy {
		return sc.unhappyRun(ctx, childEnv)
	}
	return sc.happyRun(ctx, childEnv)
}

// happyRun tests that trust is transferred to a new light block when consensus
// chain context changes if validator set has enough votes.
//
// It consists of 3 steps:
//   - Build a simple key/value and key manager runtime with an embedded trust
//     root, register them to the network together and test that everything
//     works.
//   - Do dump/restore procedure which simulates a real network upgrade.
//     This step will stop the network, clear everything except runtime's
//     local storage (we need it as the verifier has last trust root
//     stored in it) and change consensus chain context. The latter will
//     force the verifier to check if transition to a new light block
//     is possible.
//   - Start the network and test if everything works.
//   - Repeat last two points. Chain context transition can be done repeatedly,
//     as long as new light blocks are trusted and valid.
func (sc *trustRootChangeImpl) happyRun(ctx context.Context, childEnv *env.Env) (err error) {
	// Step 1: Build a simple key/value runtime and start the network.
	if err = sc.PreRun(ctx, childEnv); err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, sc.PostRun(ctx, childEnv))
	}()

	// All chain contexts should be unique.
	chainContexts := make(map[string]struct{})
	c, err := sc.ChainContext(ctx)
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
		c, err = sc.ChainContext(ctx)
		if err != nil {
			return err
		}
		if _, ok := chainContexts[c]; ok {
			return fmt.Errorf("chain context hasn't changed")
		}
		chainContexts[c] = struct{}{}

		// Test runtime to be sure that blocks get processed correctly.
		// We do this by checking if key/value store was successfully restored.
		if err := sc.startClientComputeAndKeyManagerNodes(ctx, childEnv); err != nil {
			return err
		}
		if err := sc.startRestoredStateTestClient(ctx, childEnv, round); err != nil {
			return err
		}
	}

	// Check logs whether any issues were detected.
	return sc.Net.CheckLogWatchers()
}

// unhappyRun tests that trust is never transferred to untrusted or invalid
// light blocks when consensus chain context changes.
//
// It consists of 5 steps:
//   - Build a simple key/value and key manager runtime with an embedded trust
//     root, register them to the network together and test that everything
//     works.
//   - Stop the network, set genesis height to 1 and reset the consensus state.
//     This will cause a chain context change when the network will be started
//     again. When doing state wipe be careful not to delete compute workers
//     and key manager local storages as they contain sealed trusted roots.
//   - Start the network. If everything works as expected, key manager nodes
//     should never be ready as the verifier cannot transfer trust the light
//     blocks on a new chain. As a consequence, the runtime workers will get
//     stuck waiting for available key manager.
//   - Repeat last two points. This time set genesis height to something big
//     and remove one validator from the set so that we can simulate what
//     happens when the new validator set has only 2/3 of the voting power.
func (sc *trustRootChangeImpl) unhappyRun(ctx context.Context, childEnv *env.Env) (err error) {
	// Step 1: Build a simple key/value runtime and start the network.
	if err = sc.PreRun(ctx, childEnv); err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, sc.PostRun(ctx, childEnv))
	}()

	chainContext, err := sc.ChainContext(ctx)
	if err != nil {
		return err
	}

	// Prepare functions for dump/restore procedures.
	nodeID := sc.Net.Validators()[2].NodeID // Selected for removal in step 4.

	f := []func(fixture *oasis.NetworkFixture){
		// First dump with too low genesis height.
		func(fixture *oasis.NetworkFixture) {
			// We only need one compute worker and one key manager node.
			fixture.Keymanagers = fixture.Keymanagers[:1]
			fixture.ComputeWorkers = fixture.ComputeWorkers[:1]
			fixture.Clients = fixture.Clients[:0]

			// Start both nodes after dump-restore.
			fixture.Keymanagers[0].NoAutoStart = false
			fixture.ComputeWorkers[0].NoAutoStart = false

			// Observe logs for invalid genesis block error messages.
			fixture.Keymanagers[0].LogWatcherHandlerFactories = []log.WatcherHandlerFactory{
				oasis.LogAssertEvent(LogEventTrustRootChangeFailed, "the verifier should emit invalid genesis block event"),
			}
		},

		// Second dump without one validator.
		func(fixture *oasis.NetworkFixture) {
			// Remove one validator so that trust validation will fail.
			fixture.Validators = fixture.Validators[:2]

			// We only need one compute worker and one key manager node.
			fixture.Keymanagers = fixture.Keymanagers[:1]
			fixture.ComputeWorkers = fixture.ComputeWorkers[:1]
			fixture.Clients = fixture.Clients[:0]

			// Start both nodes after dump-restore.
			fixture.Keymanagers[0].NoAutoStart = false
			fixture.ComputeWorkers[0].NoAutoStart = false

			// Observe logs for not enough trust error messages.
			fixture.Keymanagers[0].LogWatcherHandlerFactories = []log.WatcherHandlerFactory{
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
		if err = sc.WaitNodesSynced(ctx); err != nil {
			return err
		}

		// Assert that chain context has changed. Test is meaningless if this
		// doesn't happen.
		newChainContext, err := sc.ChainContext(ctx)
		if err != nil {
			return err
		}
		if newChainContext == chainContext {
			return fmt.Errorf("chain context hasn't changed")
		}

		// The key manager should now have a problem starting the key manager
		// runtime as the verifier will never initialize. As a consequence,
		// the runtime worker will get stuck waiting for available key manager.
		func() {
			waitCtx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()

			_ = sc.Net.Keymanagers()[0].WaitReady(waitCtx)
		}()

		// Verify that the compute worker is stuck.
		ctrl, err := oasis.NewController(sc.Net.ComputeWorkers()[0].SocketPath())
		if err != nil {
			return err
		}
		status, err := ctrl.GetStatus(ctx)
		if err != nil {
			return err
		}
		rtStatus, ok := status.Runtimes[sc.Net.Runtimes()[1].ID()]
		if !ok {
			return fmt.Errorf("runtime not supported by the compute worker")
		}
		if rtStatus.Committee.Status != commonWorker.StatusStateWaitingKeymanager {
			return fmt.Errorf("compute worker should be waiting for available key manager")
		}

		// Verify that the key manager node failed to trust the new trust root.
		if err := sc.Net.CheckLogWatchers(); err != nil {
			return err
		}
	}

	return nil
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
	return sc.DumpRestoreNetwork(childEnv, fixture, false, g, resetFlags)
}

func (sc *trustRootChangeImpl) startRestoredStateTestClient(ctx context.Context, childEnv *env.Env, round int64) error {
	// Check that everything works with restored state.
	seed := fmt.Sprintf("seed %d", round)
	sc.Scenario.TestClient = NewTestClient().WithSeed(seed).WithScenario(RemoveEncWithSecretsScenario)
	return sc.Scenario.Run(ctx, childEnv)
}
