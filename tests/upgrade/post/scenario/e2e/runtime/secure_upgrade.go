package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e/runtime"

	"github.com/oasisprotocol/oasis-core/test-upgrade/scenario/e2e"
)

var (
	// SecureUpgrade is a pre-upgrade part of the scenario in which we upgrade
	// the simple key/value and key manager runtimes, utilize trust roots for
	// consensus verification, and test the functionality of master secret rotations.
	SecureUpgrade scenario.Scenario = newSecureUpgradeImpl()

	secureUpgradePreTestScenario = runtime.NewTestClientScenario([]interface{}{
		// Test that pre-upgrade key/value pairs are still in the database.
		runtime.GetKeyValueTx{Key: "pre-key1", Response: "pre-value1", Encrypted: false},
		runtime.GetKeyValueTx{Key: "pre-key2", Response: "pre-value2", Encrypted: true, Generation: 0},
		runtime.GetKeyValueTx{Key: "pre-key1", Response: "", Encrypted: true, Generation: 0},
		runtime.GetKeyValueTx{Key: "pre-key2", Response: "", Encrypted: false},
		// Insert post-upgrade key/value pairs, one in plaintext and one encrypted.
		runtime.InsertKeyValueTx{Key: "post-key1", Value: "post-value1", Response: "", Encrypted: false},
		runtime.InsertKeyValueTx{Key: "post-key2", Value: "post-value2", Response: "", Encrypted: true, Generation: 0},
		// Test that post-upgrade key/value pairs were correctly inserted into the database.
		runtime.GetKeyValueTx{Key: "post-key1", Response: "post-value1", Encrypted: false},
		runtime.GetKeyValueTx{Key: "post-key2", Response: "post-value2", Encrypted: true, Generation: 0},
		// Test that post-upgrade key/value pairs are either in plaintext or encrypted.
		runtime.GetKeyValueTx{Key: "post-key1", Response: "", Encrypted: true, Generation: 0},
		runtime.GetKeyValueTx{Key: "post-key2", Response: "", Encrypted: false},
	})

	secureUpgradePostTestScenario = runtime.NewTestClientScenario([]interface{}{
		// Test that pre-upgrade key/value pairs are still in the database.
		runtime.GetKeyValueTx{Key: "pre-key1", Response: "pre-value1", Encrypted: false},
		runtime.GetKeyValueTx{Key: "pre-key2", Response: "pre-value2", Encrypted: true, Generation: 0},
		runtime.GetKeyValueTx{Key: "pre-key1", Response: "", Encrypted: true, Generation: 0},
		runtime.GetKeyValueTx{Key: "pre-key2", Response: "", Encrypted: false},
		// Test that post-upgrade key/value pairs are still in the database.
		runtime.GetKeyValueTx{Key: "post-key1", Response: "post-value1", Encrypted: false},
		runtime.GetKeyValueTx{Key: "post-key2", Response: "post-value2", Encrypted: true, Generation: 0},
		runtime.GetKeyValueTx{Key: "post-key1", Response: "", Encrypted: true, Generation: 0},
		runtime.GetKeyValueTx{Key: "post-key2", Response: "", Encrypted: false},
		// Test master secret generations.
		runtime.InsertKeyValueTx{Key: "msgn-key1", Value: "msgn-value1", Response: "", Encrypted: true, Generation: 0},
		runtime.InsertKeyValueTx{Key: "msgn-key2", Value: "msgn-value2", Response: "", Encrypted: true, Generation: 1},
		runtime.InsertKeyValueTx{Key: "msgn-key3", Value: "msgn-value3", Response: "", Encrypted: true, Generation: 2},
		runtime.GetKeyValueTx{Key: "msgn-key1", Response: "msgn-value1", Encrypted: true, Generation: 0},
		runtime.GetKeyValueTx{Key: "msgn-key2", Response: "msgn-value2", Encrypted: true, Generation: 1},
		runtime.GetKeyValueTx{Key: "msgn-key3", Response: "msgn-value3", Encrypted: true, Generation: 2},
	})

	invalidSecureUpgradeTestScenario = runtime.NewTestClientScenario([]interface{}{
		// Test that key/value pair cannot be encrypted with a master secret from the future.
		runtime.InsertKeyValueTx{Key: "msgn-key4", Value: "msgn-value4", Response: "", Encrypted: true, Generation: 1000},
	})
)

type secureUpgradeImpl struct {
	runtime.Scenario

	upgradedRuntimeIndex    int
	upgradedKeyManagerIndex int
}

func newSecureUpgradeImpl() scenario.Scenario {
	return &secureUpgradeImpl{
		Scenario: *runtime.NewScenario(
			"trust-root/secure-upgrade",
			runtime.NewTestClient().WithSeed("post-seed").WithScenario(secureUpgradePreTestScenario),
		),
	}
}

func (sc *secureUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// We need to upgrade the compute runtime and the key manager runtime
	// as the old ones do not support master secret generations.
	if sc.upgradedRuntimeIndex, err = sc.UpgradeComputeRuntimeFixture(f); err != nil {
		return nil, err
	}
	if sc.upgradedKeyManagerIndex, err = sc.UpgradeKeyManagerFixture(f); err != nil {
		return nil, err
	}

	// Make sure no nodes are started initially as we need to determine the trust root
	// and build an appropriate runtime with the trust root embedded.
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].NoAutoStart = true
	}
	for i := range f.Clients {
		f.Clients[i].NoAutoStart = true
	}

	// Address books need to be empty, because the validators use different ports
	// in the new version.
	for i := range f.Seeds {
		f.Seeds[i].DisableAddrBookFromGenesis = true
	}

	// Use the same non-debug entity as in the pre-upgrade scenario.
	f.Entities[1].Restore = true

	return f, nil
}

func (sc *secureUpgradeImpl) Clone() scenario.Scenario {
	return &secureUpgradeImpl{
		Scenario: *sc.Scenario.Clone().(*runtime.Scenario),
	}
}

func (sc *secureUpgradeImpl) Run(ctx context.Context, childEnv *env.Env) error {
	// Fix the exported genesis file and use it.
	cli := cli.New(childEnv, sc.Net, sc.Logger)
	genesisFile, err := e2e.FixExportedGenesisFile(childEnv, cli, &sc.Scenario.Scenario)
	if err != nil {
		return err
	}
	cfg := sc.Net.Config()
	cfg.GenesisFile = genesisFile

	// Update CLI helpers config as we have just changed the genesis file.
	cli.SetConfig(sc.Net.GetCLIConfig())

	// Remove address books.
	for _, n := range sc.Net.Seeds() {
		if err = os.RemoveAll(filepath.Join(n.DataDir(), "tendermint-seed")); err != nil {
			return err
		}
	}

	// Start generating blocks.
	if err = sc.Net.Start(); err != nil {
		return err
	}
	if err = sc.Net.Controller().WaitNodesRegistered(ctx, len(sc.Net.Validators())); err != nil {
		return err
	}

	// Pick one block and use it as an embedded trust root.
	trustRoot, err := sc.TrustRoot(ctx)
	if err != nil {
		return err
	}

	// Build simple key/value and key manager runtimes.
	defer func() {
		err2 := sc.BuildAllRuntimes(childEnv, nil)
		err = multierror.Append(err, err2).ErrorOrNil()
	}()
	if err = sc.BuildAllRuntimes(childEnv, trustRoot); err != nil {
		return err
	}

	// Refresh the bundles, keeping the current bundles intact. This needs to be done before
	// setting the key manager policy, to ensure enclave IDs are correct.
	if err = sc.Net.Runtimes()[sc.upgradedRuntimeIndex].RefreshRuntimeBundle(1); err != nil {
		return fmt.Errorf("failed to refresh runtime bundle: %w", err)
	}
	if err = sc.Net.Runtimes()[sc.upgradedKeyManagerIndex].RefreshRuntimeBundles(); err != nil {
		return fmt.Errorf("failed to refresh runtime bundle: %w", err)
	}

	// Start all workers and run the test client.
	if err = sc.startClientAndComputeWorkers(ctx); err != nil {
		return nil
	}
	if err = sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}

	// The test client scenario passed, indicating that the key/value pairs from the database were
	// successfully fetched. The storage of both the simple key/value runtime and the simple key
	// manager runtime has not been affected by the node upgrade. Furthermore, the insertion
	// of new key/value pairs also works.

	// Upgrade the compute runtime.
	nonce, err := sc.TestEntityNonce(ctx)
	if err != nil {
		return err
	}
	if err := sc.UpgradeComputeRuntime(ctx, childEnv, cli, sc.upgradedRuntimeIndex, nonce); err != nil {
		return err
	}

	// The key manager upgrade scenario added an upgraded key manager node to the network,
	// so we need to re-register the entity.
	ent := sc.Net.Entities()[1]
	nonce, err = sc.EntityNonceByID(ctx, ent.ID())
	if err != nil {
		return nil
	}
	if err = sc.RegisterEntity(childEnv, cli, ent, nonce); err != nil {
		return err
	}

	// Upgrade the key manager runtime.
	nonce, err = sc.TestEntityNonce(ctx)
	if err != nil {
		return err
	}
	if err := sc.UpgradeKeyManager(ctx, childEnv, cli, sc.upgradedKeyManagerIndex, nonce); err != nil {
		return err
	}

	// Enable master secret rotations.
	nonce, err = sc.TestEntityNonce(ctx)
	if err != nil {
		return err
	}
	if err = sc.UpdateRotationInterval(ctx, childEnv, cli, 1, nonce); err != nil {
		return err
	}

	// Wait until at least 3 secrets are generated.
	if _, err = sc.WaitMasterSecret(ctx, 3); err != nil {
		return err
	}

	// Run the test client again.
	sc.TestClient.WithScenario(secureUpgradePostTestScenario)
	if err = sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}

	// Run the test client again, but expect it to fail this time as the requested master secret
	// generation is not yet available.
	sc.TestClient.WithScenario(invalidSecureUpgradeTestScenario)
	err = sc.RunTestClientAndCheckLogs(ctx, childEnv)
	switch {
	case err == nil:
		return fmt.Errorf("master secret generation should be from the future")
	case strings.Contains(err.Error(), "generation is in the future"):
		return nil
	default:
		return err
	}
}

func (sc *secureUpgradeImpl) startClientAndComputeWorkers(ctx context.Context) error {
	for _, n := range sc.Net.ComputeWorkers() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}
	for _, n := range sc.Net.Clients() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}
	for _, node := range sc.Net.ComputeWorkers() {
		if err := node.WaitReady(ctx); err != nil {
			return err
		}
	}
	for _, node := range sc.Net.Clients() {
		if err := node.WaitReady(ctx); err != nil {
			return err
		}
	}

	// Setup a client controller as there is none due to the client node not
	// being auto-started.
	ctrl, err := oasis.NewController(sc.Net.Clients()[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create client controller: %w", err)
	}
	sc.Net.SetClientController(ctrl)

	return nil
}
