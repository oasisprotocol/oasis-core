package runtime

import (
	"context"
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	// cfgNumMasterSecrets is the number of master secrets to replicate.
	cfgNumMasterSecrets = "num_master_secrets" // #nosec G101

	// cfgRotationInterval is the master secret rotation interval.
	cfgRotationInterval = "rotation_interval"
)

// KeymanagerReplicateMany is a scenario where a large number of master secrets are generated
// and replicated. Its purpose is to benchmark how long replication takes on a local SGX machine.
//
// Scenario:
//   - Start the first two key managers.
//   - Generate N master secrets.
//   - Start the last two key managers.
//   - Start a timer.
//   - Wait until the master secrets are replicated.
//   - Stop the timer.
//   - Verify that all key managers possess the same secrets.
//   - Verify that master secret generation still works.
var KeymanagerReplicateMany scenario.Scenario = newKmReplicateManyImpl()

type kmReplicateManyImpl struct {
	Scenario
}

func newKmReplicateManyImpl() scenario.Scenario {
	sc := kmReplicateManyImpl{
		Scenario: *NewScenario("keymanager-replication-many", nil),
	}
	sc.Flags.Uint64(cfgNumMasterSecrets, 5, "number of master secrets to replicate")
	sc.Flags.Uint64(cfgRotationInterval, 1, "master secret rotation interval")

	return &sc
}

func (sc *kmReplicateManyImpl) Clone() scenario.Scenario {
	return &kmReplicateManyImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmReplicateManyImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Speed up the test.
	f.Network.Beacon.VRFParameters = &beacon.VRFParameters{
		Interval:             10,
		ProofSubmissionDelay: 2,
	}

	// We don't need compute workers.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}

	// This requires multiple keymanagers.
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1, Policy: 0},
		{Runtime: 0, Entity: 1, Policy: 0},
		{Runtime: 0, Entity: 1, Policy: 0, NodeFixture: oasis.NodeFixture{NoAutoStart: true}},
		{Runtime: 0, Entity: 1, Policy: 0, NodeFixture: oasis.NodeFixture{NoAutoStart: true}},
	}

	// Enable master secret rotation.
	interval, _ := sc.Flags.GetUint64(cfgRotationInterval)
	f.KeymanagerPolicies[0].MasterSecretRotationInterval = beacon.EpochTime(interval)

	return f, nil
}

func (sc *kmReplicateManyImpl) Run(ctx context.Context, childEnv *env.Env) error {
	// Fetch the number of secrets to replicate.
	n, _ := sc.Flags.GetUint64(cfgNumMasterSecrets)
	if n == 0 {
		return fmt.Errorf("the number of master secrets must be a positive value")
	}
	generation := n - 1

	// Start the first two key managers.
	if err := sc.Net.Start(); err != nil {
		return err
	}

	// Wait until master secrets are generated.
	if _, err := sc.waitMasterSecret(ctx, generation); err != nil {
		return err
	}

	// Start the last two key managers.
	if err := sc.startKeymanagers(ctx, []int{2, 3}); err != nil {
		return err
	}

	// Wait until all secrets are replicated.
	start := time.Now()

	if err := sc.waitKeymanagers(ctx, []int{2, 3}); err != nil {
		return err
	}

	sc.Logger.Info("replication finished",
		"duration", time.Since(start),
	)

	// Compare public keys.
	if err := sc.compareLongtermPublicKeys(ctx, []int{0, 1, 2, 3}); err != nil {
		return err
	}

	// Verify that secret can be generated after replication.
	status, err := sc.keymanagerStatus(ctx)
	if err != nil {
		return err
	}
	status, err = sc.waitMasterSecret(ctx, status.Generation+2)
	if err != nil {
		return err
	}

	// Verify that all nodes formed the committee when the last secret was generated.
	if size := len(status.Nodes); size != 4 {
		return fmt.Errorf("key manager committee's size is not correct: expected 4, got %d", size)
	}

	return nil
}
