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

var (
	insertEncWithChurpScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", 0, 0, encryptedWithChurpTxKind},
		GetKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithChurpTxKind},
		RemoveKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithChurpTxKind},
		GetKeyValueTx{"my_key", "", 0, 0, encryptedWithChurpTxKind},
		InsertKeyValueTx{"my_key", "my_value", "", 0, 0, encryptedWithChurpTxKind},
	})

	getEncWithChurpScenario = NewTestClientScenario([]interface{}{
		GetKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithChurpTxKind},
	})
)

// KeymanagerChurpTxs is the key manager CHURP scenario exercising encrypted transactions.
var KeymanagerChurpTxs scenario.Scenario = newKmChurpTxsImpl()

type kmChurpTxsImpl struct {
	Scenario
}

func newKmChurpTxsImpl() scenario.Scenario {
	return &kmChurpTxsImpl{
		Scenario: *NewScenario(
			"keymanager-churp-txs",
			NewTestClient(),
		),
	}
}

func (sc *kmChurpTxsImpl) Clone() scenario.Scenario {
	return &kmChurpTxsImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmChurpTxsImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// We need 4 key managers to test all handoff kinds.
	f.Keymanagers[0].ChurpIDs = []uint8{0}
	for i := 0; i < 3; i++ {
		f.Keymanagers = append(f.Keymanagers, f.Keymanagers[0])
	}

	// Speed up the test.
	f.Network.Beacon.VRFParameters = &beacon.VRFParameters{
		Interval:             10,
		ProofSubmissionDelay: 2,
	}

	return f, nil
}

func (sc *kmChurpTxsImpl) Run(ctx context.Context, childEnv *env.Env) error {
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

	// Create scheme. The handoff interval is set to 4 so that a newly started
	// key manager node has enough time to register. This could be lowered once
	// we refactor key manager node tracker on P2P layer.
	id := uint8(0)
	threshold := uint8(1)
	handoffInterval := beacon.EpochTime(4)
	nonce := uint64(0)

	if err = sc.createChurp(ctx, id, threshold, handoffInterval, nonce); err != nil {
		return err
	}

	// 1. Dealing phase
	sc.Logger.Info("waiting handoff to complete (dealing phase)")

	firstStatus, err := sc.waitNextHandoff(ctx, 0, 4, stCh)
	if err != nil {
		return err
	}

	sc.Logger.Info("testing handoff (dealing phase)")

	sc.TestClient.scenario = insertEncWithChurpScenario
	if err = sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}
	if err = sc.clearComputeNodeCache(ctx); err != nil {
		return err
	}

	// 2. Committee unchanged.
	sc.Logger.Info("waiting handoff to complete (committee unchanged)")

	secondStatus, err := sc.waitNextHandoff(ctx, firstStatus.Handoff, 4, stCh)
	if err != nil {
		return err
	}

	sc.Logger.Info("testing handoff (committee unchanged)")

	sc.TestClient.scenario = getEncWithChurpScenario
	if err = sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}
	if err = sc.clearComputeNodeCache(ctx); err != nil {
		return err
	}

	// Stop one key manager so that the committee changes.
	if err = sc.Net.Keymanagers()[0].Stop(); err != nil {
		return err
	}

	// 3. Committee changed (key manager removed).
	sc.Logger.Info("waiting handoff to complete (committee changed)")

	thirdStatus, err := sc.waitNextHandoff(ctx, secondStatus.Handoff, 3, stCh)
	if err != nil {
		return err
	}

	sc.Logger.Info("testing handoff (committee changed)")

	if err = sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}
	if err = sc.clearComputeNodeCache(ctx); err != nil {
		return err
	}

	// Start another key manager so that the committee changes.
	if err = sc.Net.Keymanagers()[0].Start(); err != nil {
		return err
	}
	if err = sc.Net.Keymanagers()[0].WaitReady(ctx); err != nil {
		return err
	}

	// 4. Committee changed (key manager added).
	sc.Logger.Info("waiting handoff to complete (committee changed)")

	_, err = sc.waitNextHandoff(ctx, thirdStatus.Handoff, 4, stCh)
	if err != nil {
		return err
	}

	sc.Logger.Info("testing handoff (committee changed)")

	if err = sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}

	return nil
}

func (sc *kmChurpTxsImpl) clearComputeNodeCache(ctx context.Context) error {
	for _, w := range sc.Net.ComputeWorkers() {
		if err := w.Restart(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (sc *kmChurpTxsImpl) waitNextHandoff(ctx context.Context, lastHandoff beacon.EpochTime, committeeSize int, stCh <-chan *churp.Status) (*churp.Status, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	for {
		status, err := sc.nextChurpStatus(ctx, stCh)
		if err != nil {
			return nil, err
		}
		if status.Handoff <= lastHandoff {
			continue
		}
		if n := len(status.Committee); n != committeeSize {
			return nil, fmt.Errorf("committee should have %d and not %d members", committeeSize, n)
		}
		return status, nil
	}
}
