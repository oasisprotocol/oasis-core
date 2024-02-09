package runtime

import (
	"context"
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerChurp is the key manager CHURP scenario.
var KeymanagerChurp scenario.Scenario = newKmChurpImpl()

type kmChurpImpl struct {
	Scenario
}

func newKmChurpImpl() scenario.Scenario {
	return &kmChurpImpl{
		Scenario: *NewScenario(
			"keymanager-churp",
			NewTestClient(),
		),
	}
}

func (sc *kmChurpImpl) Clone() scenario.Scenario {
	return &kmChurpImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmChurpImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// We don't need compute workers.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}

	// We need 4 key managers.
	f.Keymanagers[0].ChurpIDs = []uint8{0}
	for i := 0; i < 3; i++ {
		f.Keymanagers = append(f.Keymanagers, f.Keymanagers[0])
	}
	for i := 2; i < 4; i++ {
		f.Keymanagers[i].NoAutoStart = true
	}

	// Enable CHURP extension.
	f.Network.EnableKeyManagerCHURP = true

	// Speed up the test.
	f.Network.Beacon.VRFParameters = &beacon.VRFParameters{
		Interval:             10,
		ProofSubmissionDelay: 2,
	}

	return f, nil
}

func (sc *kmChurpImpl) Run(ctx context.Context, _ *env.Env) error { //nolint: gocyclo
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

	// Create scheme.
	id := uint8(0)
	threshold := uint8(1)
	handoffInterval := beacon.EpochTime(2)

	if err = sc.createChurp(ctx, id, threshold, handoffInterval, nonce); err != nil {
		return err
	}
	nonce++

	// The dealing round requires threshold + 2 key manager nodes.
	// Since only 2 are running, all handoffs should fail.
	sc.Logger.Info("testing dealing phase (not enough nodes)")

	var (
		status     *churp.Status
		lastStatus *churp.Status
		failed     int
	)

	for failed < 2 {
		status, err = sc.nextChurpStatus(ctx, stCh)
		if err != nil {
			return err
		}

		if status.Handoff != 0 || status.Committee != nil {
			return fmt.Errorf("dealing phase should fail")
		}
		if lastStatus != nil && lastStatus.NextHandoff != 0 {
			if status.NextHandoff-lastStatus.NextHandoff > 1 {
				return fmt.Errorf("failed handoffs should be 1 epoch apart")
			}
			if status.NextHandoff != lastStatus.NextHandoff {
				failed++
			}
		}

		lastStatus = status
	}

	// The dealing phase.
	sc.Logger.Info("testing dealing phase")

	if err = sc.Net.Keymanagers()[2].Start(); err != nil {
		return err
	}

	for status.Handoff == 0 {
		status, err = sc.nextChurpStatus(ctx, stCh)
		if err != nil {
			return err
		}
	}

	if len(status.Committee) != 3 {
		return fmt.Errorf("committee should have 3 members")
	}
	if status.Checksum == nil {
		return fmt.Errorf("checksum should be set")
	}
	if status.NextHandoff-status.Handoff != handoffInterval {
		return fmt.Errorf("invalid handoff interval")
	}

	// Committee unchanged.
	for i := 0; i < 2; i++ {
		sc.Logger.Info("testing committee unchanged",
			"round", i,
		)

		lastStatus = status
		status, err = sc.waitNextHandoff(ctx, status.Handoff, stCh)
		if err != nil {
			return err
		}

		if len(status.Committee) != 3 {
			return fmt.Errorf("committee should have 3 members")
		}
		if status.Checksum == lastStatus.Checksum {
			return fmt.Errorf("checksum should change")
		}
	}

	// Committee changed.
	for i := 0; i < 2; i++ {
		// Add node.
		sc.Logger.Info("testing committee changed (node added)",
			"round", i,
		)

		if err = sc.Net.Keymanagers()[3].Start(); err != nil {
			return err
		}

		// Ignore the first handoff as the node needs time to start.
		for j := 0; j < 2; j++ {
			lastStatus = status
			status, err = sc.waitNextHandoff(ctx, status.Handoff, stCh)
			if err != nil {
				return err
			}
		}

		if len(status.Committee) != 4 {
			return fmt.Errorf("committee should have 4 members")
		}
		if status.Checksum == lastStatus.Checksum {
			return fmt.Errorf("checksum should change")
		}

		// Remove node.
		sc.Logger.Info("testing committee changed (node removed)",
			"round", i,
		)

		if err = sc.Net.Keymanagers()[3].Stop(); err != nil {
			return err
		}

		lastStatus = status
		status, err = sc.waitNextHandoff(ctx, status.Handoff, stCh)
		if err != nil {
			return err
		}

		if len(status.Committee) != 3 {
			return fmt.Errorf("committee should have 3 members")
		}
		if status.Checksum == lastStatus.Checksum {
			return fmt.Errorf("checksum should change")
		}
	}

	// Handoffs disabled.
	sc.Logger.Info("testing handoffs disabled")

	handoffInterval = churp.HandoffsDisabled
	if err = sc.updateChurp(ctx, id, handoffInterval, nonce); err != nil {
		return err
	}
	nonce++

	// After the update, there should be no status updates.
	for status.HandoffInterval != churp.HandoffsDisabled {
		status, err = sc.nextChurpStatus(ctx, stCh)
		if err != nil {
			return err
		}
	}

	select {
	case status = <-stCh:
		sc.Logger.Info("status updated",
			"status", fmt.Sprintf("%+v", status),
		)
		return fmt.Errorf("handoffs should be disabled")
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(20 * time.Second):
	}

	// Handoffs enabled.
	sc.Logger.Info("testing handoffs enabled")

	handoffInterval = beacon.EpochTime(1)
	if err = sc.updateChurp(ctx, id, handoffInterval, nonce); err != nil {
		return err
	}

	for i := 0; i < 2; i++ {
		lastStatus = status
		status, err = sc.waitNextHandoff(ctx, status.Handoff, stCh)
		if err != nil {
			return err
		}
	}

	if status.Handoff-lastStatus.Handoff != handoffInterval {
		return fmt.Errorf("invalid handoff interval")
	}

	return nil
}

func (sc *kmChurpImpl) waitNextHandoff(ctx context.Context, epoch beacon.EpochTime, stCh <-chan *churp.Status) (*churp.Status, error) {
	for {
		status, err := sc.nextChurpStatus(ctx, stCh)
		if err != nil {
			return nil, err
		}
		if status.Handoff <= epoch {
			continue
		}
		return status, nil
	}
}
