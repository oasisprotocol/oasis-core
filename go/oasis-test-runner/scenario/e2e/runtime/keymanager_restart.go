package runtime

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerRestart is the keymanager restart scenario.
var KeymanagerRestart scenario.Scenario = newKmRestartImpl()

type kmRestartImpl struct {
	Scenario
}

func newKmRestartImpl() scenario.Scenario {
	return &kmRestartImpl{
		Scenario: *NewScenario(
			"keymanager-restart",
			NewKVTestClient().WithScenario(InsertRemoveKeyValueEncScenario),
		),
	}
}

func (sc *kmRestartImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Speed up the test.
	f.Network.Beacon.VRFParameters = &beacon.VRFParameters{
		Interval:             10,
		ProofSubmissionDelay: 2,
	}

	// This requires multiple keymanagers.
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1, Policy: 0},
		{Runtime: 0, Entity: 1, Policy: 0},
		{Runtime: 0, Entity: 1, Policy: 0},
	}

	// The round is allowed to fail until the keymanager becomes available after restart.
	f.Network.DefaultLogWatcherHandlerFactories = nil

	// Enable master secret rotation.
	f.KeymanagerPolicies[0].MasterSecretRotationInterval = 1

	return f, nil
}

func (sc *kmRestartImpl) Clone() scenario.Scenario {
	return &kmRestartImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmRestartImpl) Run(ctx context.Context, childEnv *env.Env) error {
	if err := sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	// Wait for the client to exit.
	if err := sc.WaitTestClient(); err != nil {
		return err
	}

	// Wait until 3 master secrets are generated.
	if _, err := sc.WaitMasterSecret(ctx, 2); err != nil {
		return fmt.Errorf("master secret not generated: %w", err)
	}

	// Restart the key managers.
	if err := sc.RestartAndWaitKeymanagers(ctx, []int{0, 1, 2}); err != nil {
		return err
	}

	// Test if rotations still work.
	if _, err := sc.WaitMasterSecret(ctx, 5); err != nil {
		return err
	}

	// Run the second client on a different key so that it will require
	// a second trip to the keymanager.
	sc.Logger.Info("starting a second client to check if key manager works")
	sc.Scenario.testClient = NewKVTestClient().WithSeed("seed2").WithScenario(InsertRemoveKeyValueEncScenarioV2)
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}
