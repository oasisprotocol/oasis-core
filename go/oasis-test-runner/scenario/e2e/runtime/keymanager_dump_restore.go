package runtime

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerDumpRestore is the keymanager dump restore rotation scenario.
//
// In this scenario we test if the deployment of the master secret rotation
// feature is backwards compatible. The old key managers which are already
// initialized with the first master secret should be able to rotate secrets
// once enabled via the policy.
var KeymanagerDumpRestore scenario.Scenario = newKmDumpRestoreImpl()

type kmDumpRestoreImpl struct {
	Scenario

	nonce uint64
}

func newKmDumpRestoreImpl() scenario.Scenario {
	return &kmDumpRestoreImpl{
		Scenario: *NewScenario(
			"keymanager-dump-restore",
			NewKVTestClient().WithScenario(InsertRemoveKeyValueEncScenario),
		),
	}
}

func (sc *kmDumpRestoreImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Speed up the test.
	f.Network.Beacon.VRFParameters = &beacon.VRFParameters{
		Interval:             10,
		ProofSubmissionDelay: 2,
	}

	// Compute workers are not needed.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}

	// Test requires multiple key managers.
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1},
		{Runtime: 0, Entity: 1},
	}

	return f, nil
}

func (sc *kmDumpRestoreImpl) Clone() scenario.Scenario {
	return &kmDumpRestoreImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmDumpRestoreImpl) Run(ctx context.Context, childEnv *env.Env) (err error) { // nolint: gocyclo
	// Start the network.
	if err = sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}

	// Wait until the first master secret is generated.
	if _, err = sc.waitMasterSecret(ctx, 0); err != nil {
		return err
	}

	// Dump/restore should erase the last master secret and leave the key manager initialized.
	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}
	for i := range fixture.Keymanagers {
		fixture.Keymanagers[i].NoAutoStart = true
	}
	if err = sc.DumpRestoreNetwork(childEnv, fixture, false, nil, nil); err != nil {
		return err
	}

	// Start the network.
	if err = sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}

	// Make sure the last secret was not preserved.
	secret, err := sc.keymanagerMasterSecret(ctx)
	if err != nil {
		return err
	}
	if secret != nil {
		return fmt.Errorf("dump/restore should not preserve the master secret proposal")
	}

	// Make sure the manager is initialized.
	status, err := sc.keymanagerStatus(ctx)
	if err != nil {
		return err
	}
	if !status.IsInitialized || len(status.Checksum) == 0 || status.Generation != 0 {
		return fmt.Errorf("key manager should be initialized")
	}

	// Start both key manager nodes.
	if err = sc.startAndWaitKeymanagers(ctx, []int{0, 1}); err != nil {
		return err
	}

	// Test master secret rotations. To enable them, update the rotation interval in the policy.
	if err = sc.updateRotationInterval(ctx, sc.nonce, childEnv, 1); err != nil {
		return err
	}
	sc.nonce++
	if _, err = sc.waitMasterSecret(ctx, 3); err != nil {
		return err
	}

	// Test if all key managers can derive keys from all master secrets.
	if err = sc.compareLongtermPublicKeys(ctx, []int{0, 1}); err != nil {
		return err
	}

	return nil
}
