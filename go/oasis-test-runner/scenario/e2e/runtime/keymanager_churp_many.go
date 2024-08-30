package runtime

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerChurpMany is the key manager CHURP scenario with multiple schemes.
var KeymanagerChurpMany scenario.Scenario = newKmChurpManyImpl()

type kmChurpManyImpl struct {
	Scenario
}

func newKmChurpManyImpl() scenario.Scenario {
	return &kmChurpManyImpl{
		Scenario: *NewScenario(
			"keymanager-churp-many",
			NewTestClient(),
		),
	}
}

func (sc *kmChurpManyImpl) Clone() scenario.Scenario {
	return &kmChurpManyImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmChurpManyImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// We don't need compute workers.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}

	// We need 6 key managers for 3 schemes (012+5, 234+5, 01234+5).
	for i := 0; i < 5; i++ {
		f.Keymanagers = append(f.Keymanagers, f.Keymanagers[0])
	}
	f.Keymanagers[0].ChurpIDs = []uint8{0, 2}
	f.Keymanagers[1].ChurpIDs = []uint8{0, 2}
	f.Keymanagers[2].ChurpIDs = []uint8{0, 1, 2}
	f.Keymanagers[3].ChurpIDs = []uint8{1, 2}
	f.Keymanagers[4].ChurpIDs = []uint8{1, 2}
	f.Keymanagers[5].ChurpIDs = []uint8{0, 1, 2}
	f.Keymanagers[5].NoAutoStart = true

	// Speed up the test.
	f.Network.Beacon.VRFParameters = &beacon.VRFParameters{
		Interval:             10,
		ProofSubmissionDelay: 2,
	}

	return f, nil
}

func (sc *kmChurpManyImpl) Run(ctx context.Context, _ *env.Env) error {
	var nonce uint64

	if err := sc.Net.Start(); err != nil {
		return err
	}

	if err := sc.Net.ClientController().WaitReady(ctx); err != nil {
		return err
	}

	stCh, stSub, err := sc.Net.ClientController().Keymanager.Churp().WatchStatuses(ctx)
	if err != nil {
		return err
	}
	defer stSub.Close()

	// Create schemes.
	schemes := []struct {
		id              uint8
		threshold       uint8
		handoffInterval beacon.EpochTime
		numNodes        int
	}{
		{0, 0, 1, 4},
		{1, 1, 2, 4},
		{2, 2, 3, 6},
	}
	for _, s := range schemes {
		if err = sc.createChurp(ctx, s.id, s.threshold, s.handoffInterval, nonce); err != nil {
			return err
		}
		nonce++
	}

	// Dealing phase + committee unchanged.
	sc.Logger.Info("testing dealing phase and committee unchanged")

	var status *churp.Status
	lastStatuses := make(map[uint8]*churp.Status)
	handoffs := make(map[uint8]int)

	wait := true
	for wait {
		status, err = sc.nextChurpStatus(ctx, stCh)
		if err != nil {
			return err
		}

		lastStatus, ok := lastStatuses[status.ID]
		lastStatuses[status.ID] = status
		if !ok || lastStatus.Handoff == status.Handoff {
			continue
		}

		if lastStatus.Handoff != 0 && status.Handoff-lastStatus.Handoff != status.HandoffInterval {
			return fmt.Errorf("invalid handoff interval")
		}
		if lastStatus.Checksum == status.Checksum {
			return fmt.Errorf("checksum should change")
		}

		handoffs[status.ID]++

		// Wait until all schemes do the dealing phase and at least 2 handoffs
		// where committee doesn't change.
		wait = false
		for _, n := range handoffs {
			if n < 3 {
				wait = true
				break
			}
		}
	}

	// Committee changed.
	waitCommitteeChange := func(diff int) error {
		wait = true
		for wait {
			status, err = sc.nextChurpStatus(ctx, stCh)
			if err != nil {
				return err
			}

			lastStatuses[status.ID] = status

			// Wait until all schemes add or remove the new node.
			wait = false
			for _, scheme := range schemes {
				lastStatus := lastStatuses[scheme.id]
				if len(lastStatus.Committee) != scheme.numNodes-diff {
					wait = true
					break
				}
			}
		}

		return nil
	}

	// Add node.
	sc.Logger.Info("testing committee changed (node added)")

	if err = sc.Net.Keymanagers()[5].Start(); err != nil {
		return err
	}
	if err = waitCommitteeChange(0); err != nil {
		return err
	}

	// Remove node.
	sc.Logger.Info("testing committee changed (node removed)")

	if err = sc.Net.Keymanagers()[2].Stop(); err != nil {
		return err
	}
	if err = waitCommitteeChange(1); err != nil {
		return err
	}

	return nil
}
