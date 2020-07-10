package runtime

import (
	"time"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// LateStart is the LateStart node basic scenario.
var LateStart scenario.Scenario = newLateStartImpl("late-start", "simple-keyvalue-client", nil)

const lateStartInitialWait = 2 * time.Minute

type lateStartImpl struct {
	runtimeImpl
}

func newLateStartImpl(name, clientBinary string, clientArgs []string) scenario.Scenario {
	return &lateStartImpl{
		runtimeImpl: *newRuntimeImpl(name, clientBinary, clientArgs),
	}
}

func (sc *lateStartImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Start without a client.
	f.Clients = []oasis.ClientFixture{}

	return f, nil
}

func (sc *lateStartImpl) Run(childEnv *env.Env) error {
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
	clientFixture := &oasis.ClientFixture{}
	client, err := clientFixture.Create(sc.Net)
	if err != nil {
		return err
	}
	if err = client.Start(); err != nil {
		return err
	}

	sc.Logger.Info("Starting the basic client")
	cmd, err := sc.startClient(childEnv)
	if err != nil {
		return err
	}
	clientErrCh := make(chan error)
	go func() {
		clientErrCh <- cmd.Wait()
	}()

	return sc.wait(childEnv, cmd, clientErrCh)
}
