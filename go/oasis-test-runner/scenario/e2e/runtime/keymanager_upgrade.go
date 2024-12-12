package runtime

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerUpgrade is the keymanager upgrade scenario.
var KeymanagerUpgrade scenario.Scenario = NewKmUpgradeImpl()

// KmUpgradeImpl is a base class for keymanager upgrade end-to-end tests.
type KmUpgradeImpl struct {
	Scenario

	upgradedKeyManagerIndex int
}

// NewKmUpgradeImpl creates a new base scenario for oasis-node keymanager upgrade end-to-end tests.
func NewKmUpgradeImpl() scenario.Scenario {
	return &KmUpgradeImpl{
		Scenario: *NewScenario(
			"keymanager-upgrade",
			NewTestClient().WithScenario(InsertRemoveEncWithSecretsScenario),
		),
	}
}

func (sc *KmUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	if sc.upgradedKeyManagerIndex, err = sc.UpgradeKeyManagerFixture(f, true); err != nil {
		return nil, err
	}

	f.Network.RuntimeAttestInterval = 2 * time.Minute
	f.Network.RuntimeDefaultMaxAttestationAge = 200 // 4 min at 1.2 sec per block.

	return f, nil
}

func (sc *KmUpgradeImpl) Clone() scenario.Scenario {
	return &KmUpgradeImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *KmUpgradeImpl) Run(ctx context.Context, childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Start the network and run the test client.
	if err := sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}
	if err := sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}

	// Discover bundles.
	bundles, err := findBundles(sc.Net.BasePath())
	if err != nil {
		return err
	}

	// Determine the port on which the nodes are trying to fetch bundles.
	rawURL := sc.Net.Clients()[0].Config.Runtime.Repositories[0]
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	port := parsedURL.Port()

	// Start serving bundles.
	server := newBundleServer(port, bundles)
	server.Start()
	defer server.Stop()

	// Upgrade the key manager runtime.
	if err := sc.UpgradeKeyManager(ctx, childEnv, cli, sc.upgradedKeyManagerIndex, 0); err != nil {
		return err
	}

	// Verify that all key manager nodes requested bundle from the server.
	n := len(sc.Net.Keymanagers())
	if m := server.getRequestCount(); m != n {
		return fmt.Errorf("invalid number of bundle requests (got: %d, expected: %d)", m, n)
	}

	// Run client again.
	sc.Logger.Info("starting a second client to check if key manager works")
	sc.Scenario.TestClient = NewTestClient().WithSeed("seed2").WithScenario(InsertRemoveEncWithSecretsScenarioV2)
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}
