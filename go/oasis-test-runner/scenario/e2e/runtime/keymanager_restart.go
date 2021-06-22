package runtime

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerRestart is the keymanager restart scenario.
var KeymanagerRestart scenario.Scenario = newKmRestartImpl()

type kmRestartImpl struct {
	runtimeImpl
}

func newKmRestartImpl() scenario.Scenario {
	return &kmRestartImpl{
		runtimeImpl: *newRuntimeImpl(
			"keymanager-restart",
			NewBinaryTestClient(
				"simple-keyvalue-enc-client",
				[]string{
					"--key", "key1",
					"--seed", "first_seed",
				},
			),
		),
	}
}

func (sc *kmRestartImpl) Clone() scenario.Scenario {
	return &kmRestartImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *kmRestartImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	// Wait for the client to exit.
	if err := sc.waitTestClientOnly(); err != nil {
		return err
	}

	// XXX: currently assumes single keymanager.
	km := sc.Net.Keymanagers()[0]

	// Restart the key manager.
	sc.Logger.Info("restarting the key manager")
	if err := km.Restart(ctx); err != nil {
		return err
	}

	// Wait for the key manager to be ready.
	sc.Logger.Info("waiting for the key manager to become ready")
	kmCtrl, err := oasis.NewController(km.SocketPath())
	if err != nil {
		return err
	}
	if err = kmCtrl.WaitReady(ctx); err != nil {
		return err
	}

	// Run the second client on a different key so that it will require
	// a second trip to the keymanager.
	sc.Logger.Info("starting a second client to check if key manager works")
	newTestClient := sc.testClient.Clone().(*BinaryTestClient)
	newTestClient.args = []string{
		"--key", "key2",
		"--seed", "second_seed",
	}
	sc.runtimeImpl.testClient = newTestClient

	if err = sc.startTestClientOnly(ctx, childEnv); err != nil {
		return err
	}
	return sc.waitTestClient()
}
