package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
)

// ClientExpire is the ClientExpire node scenario.
var ClientExpire scenario.Scenario = newClientExpireImpl("client-expire", "simple-keyvalue-client", nil)

type clientExpireImpl struct {
	runtimeImpl
}

func newClientExpireImpl(name, clientBinary string, clientArgs []string) scenario.Scenario {
	return &clientExpireImpl{
		runtimeImpl: *newRuntimeImpl(name, clientBinary, clientArgs),
	}
}

func (sc *clientExpireImpl) Clone() scenario.Scenario {
	return &clientExpireImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *clientExpireImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Make client expire all transactions instantly.
	f.Clients[0].MaxTransactionAge = 1

	return f, nil
}

func (sc *clientExpireImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()

	// Start the network.
	var err error
	if err = sc.Net.Start(); err != nil {
		return err
	}

	// Wait for client to be ready.
	client := sc.Net.Clients()[0]
	nodeCtrl, err := oasis.NewController(client.SocketPath())
	if err != nil {
		return err
	}
	if err = nodeCtrl.WaitReady(ctx); err != nil {
		return err
	}

	err = sc.submitKeyValueRuntimeInsertTx(ctx, runtimeID, "hello", "test")
	if !errors.Is(err, api.ErrTransactionExpired) {
		return fmt.Errorf("expected error: %v, got: %v", api.ErrTransactionExpired, err)
	}

	return nil
}
