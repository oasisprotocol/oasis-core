package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
)

// LateStart is the LateStart node basic scenario.
var LateStart scenario.Scenario = newLateStartImpl("late-start")

const lateStartInitialWait = 2 * time.Minute

type lateStartImpl struct {
	Scenario
}

func newLateStartImpl(name string) scenario.Scenario {
	return &lateStartImpl{
		Scenario: *NewScenario(
			name,
			NewKVTestClient().WithScenario(SimpleKeyValueScenario),
		),
	}
}

func (sc *lateStartImpl) Clone() scenario.Scenario {
	return &lateStartImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *lateStartImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Start without a client.
	f.Clients = []oasis.ClientFixture{}

	return f, nil
}

func (sc *lateStartImpl) Run(ctx context.Context, childEnv *env.Env) error {
	// Start the network.
	var err error
	if err = sc.Net.Start(); err != nil {
		return err
	}

	sc.Logger.Info("Waiting before starting the client node",
		"wait_for", lateStartInitialWait,
	)
	time.Sleep(lateStartInitialWait)

	sc.Logger.Info("Starting the client node")
	clientFixture := &oasis.ClientFixture{
		Runtimes: []int{1},
	}
	client, err := clientFixture.Create(sc.Net)
	if err != nil {
		return err
	}
	if err = client.Start(); err != nil {
		return err
	}

	ctrl, err := oasis.NewController(client.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for client: %w", err)
	}
	err = ctrl.RuntimeClient.SubmitTxNoWait(ctx, &api.SubmitTxRequest{
		RuntimeID: KeyValueRuntimeID,
		Data: cbor.Marshal(&TxnCall{
			Method: "insert",
			Args: struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			}{
				Key:   "hello",
				Value: "test",
			},
		}),
	})
	if !errors.Is(err, api.ErrNotSynced) {
		return fmt.Errorf("expected error: %v, got: %v", api.ErrNotSynced, err)
	}
	_, err = ctrl.RuntimeClient.SubmitTx(ctx, &api.SubmitTxRequest{
		RuntimeID: KeyValueRuntimeID,
		Data: cbor.Marshal(&TxnCall{
			Method: "insert",
			Args: struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			}{
				Key:   "hello",
				Value: "test",
			},
		}),
	})
	if !errors.Is(err, api.ErrNotSynced) {
		return fmt.Errorf("expected error: %v, got: %v", api.ErrNotSynced, err)
	}

	// Set the ClientController to the late-started one, so that the test
	// client works.
	sc.Net.SetClientController(ctrl)

	sc.Logger.Info("Starting the basic test client")
	// Explicitly wait for the client to sync, before starting the client.
	if err = sc.WaitForClientSync(ctx); err != nil {
		return err
	}
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}
