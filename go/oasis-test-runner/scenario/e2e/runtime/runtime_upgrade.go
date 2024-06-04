package runtime

import (
	"context"
	"time"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// RuntimeUpgrade is the runtime upgrade scenario.
var RuntimeUpgrade scenario.Scenario = newRuntimeUpgradeImpl()

const versionActivationTimeout = 15 * time.Second

type runtimeUpgradeImpl struct {
	Scenario

	upgradedRuntimeIndex int
}

func newRuntimeUpgradeImpl() scenario.Scenario {
	return &runtimeUpgradeImpl{
		Scenario: *NewScenario(
			"runtime-upgrade",
			NewTestClient().WithScenario(InsertRemoveEncWithSecretsScenario),
		),
	}
}

func (sc *runtimeUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	if sc.upgradedRuntimeIndex, err = sc.UpgradeComputeRuntimeFixture(f); err != nil {
		return nil, err
	}

	return f, nil
}

func (sc *runtimeUpgradeImpl) Clone() scenario.Scenario {
	return &runtimeUpgradeImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *runtimeUpgradeImpl) Run(ctx context.Context, childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Start the network and run the test client.
	if err := sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}
	if err := sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}

	// Upgrade the compute runtime.
	if err := sc.UpgradeComputeRuntime(ctx, childEnv, cli, sc.upgradedRuntimeIndex, 0); err != nil {
		return err
	}

	// Run client again.
	sc.Logger.Info("starting a second client to check if runtime works")
	sc.Scenario.TestClient = NewTestClient().WithSeed("seed2").WithScenario(InsertRemoveEncWithSecretsScenarioV2)
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}
