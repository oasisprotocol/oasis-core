package runtime

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerReplicate is the keymanager replication scenario.
var KeymanagerReplicate scenario.Scenario = newKmReplicateImpl()

type kmReplicateImpl struct {
	Scenario
}

func newKmReplicateImpl() scenario.Scenario {
	return &kmReplicateImpl{
		Scenario: *NewScenario(
			"keymanager-replication",
			NewTestClient().WithScenario(InsertRemoveKeyValueEncScenario),
		),
	}
}

func (sc *kmReplicateImpl) Clone() scenario.Scenario {
	return &kmReplicateImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmReplicateImpl) Fixture() (*oasis.NetworkFixture, error) {
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
	f.KeymanagerPolicies[0].MasterSecretRotationInterval = 1

	return f, nil
}

func (sc *kmReplicateImpl) Run(ctx context.Context, _ *env.Env) error {
	// Start the first two key managers.
	if err := sc.Net.Start(); err != nil {
		return err
	}

	// Wait until 3 master secrets are generated.
	if _, err := sc.WaitMasterSecret(ctx, 2); err != nil {
		return fmt.Errorf("master secret not generated: %w", err)
	}

	// Make sure exactly two key managers were generating secrets.
	status, err := sc.KeyManagerStatus(ctx)
	if err != nil {
		return err
	}
	if len(status.Nodes) != 2 {
		return fmt.Errorf("key manager committee should consist of two nodes")
	}

	// Stop the second manager.
	// Upon restarting, its master secrets will be partially synchronized (3 out of 6).
	if err = sc.Net.Keymanagers()[1].Stop(); err != nil {
		return err
	}

	// Generate another 3 master secrets.
	if _, err = sc.WaitMasterSecret(ctx, 5); err != nil {
		return fmt.Errorf("master secret not generated: %w", err)
	}

	// Make sure the first key manager was generating secrets.
	status, err = sc.KeyManagerStatus(ctx)
	if err != nil {
		return err
	}
	if len(status.Nodes) != 1 {
		return fmt.Errorf("key manager committee should consist of one node")
	}

	// Start key managers that are not running and wait until they replicate
	// master secrets from the first one.
	if err = sc.StartAndWaitKeymanagers(ctx, []int{1, 2, 3}); err != nil {
		return err
	}

	// If the replication was successful, the next key manager committee should
	// consist of all nodes.
	if status, err = sc.waitKeymanagerStatuses(ctx, 2); err != nil {
		return err
	}
	if !status.IsInitialized {
		return fmt.Errorf("key manager failed to initialize")
	}
	if len(status.Nodes) != len(sc.Net.Keymanagers()) {
		return fmt.Errorf("key manager committee should consist of all nodes")
	}
	for _, km := range sc.Net.Keymanagers() {
		if !slices.Contains(status.Nodes, km.NodeID) {
			return fmt.Errorf("node missing from key manager status")
		}
	}

	// Wait few blocks so that the key managers transition to the new secret and register
	// with the latest checksum. The latter can take some time.
	if _, err = sc.WaitBlocks(ctx, 8); err != nil {
		return err
	}

	// Check if checksums match.
	for idx := range sc.Net.Keymanagers() {
		initRsp, err := sc.KeymanagerInitResponse(ctx, idx)
		if err != nil {
			return err
		}
		if !bytes.Equal(initRsp.Checksum, status.Checksum) {
			return fmt.Errorf("key manager checksum mismatch")
		}
	}

	// If we came this far than all key managers should have the same state.
	// Let's test if they replicated the same secrets by fetching long-term
	// public keys for all generations.
	return sc.CompareLongtermPublicKeys(ctx, []int{0, 1, 2, 3})
}

func (sc *kmReplicateImpl) waitKeymanagerStatuses(ctx context.Context, n int) (*secrets.Status, error) {
	sc.Logger.Info("waiting for key manager status", "n", n)

	stCh, stSub, err := sc.Net.Controller().Keymanager.Secrets().WatchStatuses(ctx)
	if err != nil {
		return nil, err
	}
	defer stSub.Close()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case status := <-stCh:
			if !status.ID.Equal(&KeyManagerRuntimeID) {
				continue
			}
			n--
			if n <= 0 {
				return status, nil
			}
		}
	}
}
