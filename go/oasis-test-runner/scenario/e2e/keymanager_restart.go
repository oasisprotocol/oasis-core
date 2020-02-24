package e2e

import (
	"context"

	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// KeymanagerRestart is the keymanager restart scenario.
	KeymanagerRestart scenario.Scenario = newKmRestartImpl()
)

type kmRestartImpl struct {
	basicImpl
}

func newKmRestartImpl() scenario.Scenario {
	return &kmRestartImpl{
		basicImpl: *newBasicImpl(
			"keymanager-restart",
			"simple-keyvalue-enc-client",
			[]string{"--key", "key1"},
		),
	}
}

func (sc *kmRestartImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.basicImpl.start(childEnv)
	if err != nil {
		return err
	}

	// Wait for the client to exit.
	select {
	case err = <-sc.basicImpl.net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
	}
	if err != nil {
		return err
	}

	// XXX: currently assumes single keymanager.
	km := sc.basicImpl.net.Keymanagers()[0]

	// Restart the key manager.
	sc.logger.Info("restarting the key manager")
	if err = km.Restart(); err != nil {
		return err
	}

	// Wait for the key manager to be ready.
	sc.logger.Info("waiting for the key manager to become ready")
	kmCtrl, err := oasis.NewController(km.SocketPath())
	if err != nil {
		return err
	}
	if err = kmCtrl.WaitSync(context.Background()); err != nil {
		return err
	}

	// Run the second client on a different key so that it will require
	// a second trip to the keymanager.
	sc.logger.Info("starting a second client to check if key manager works")
	cmd, err = startClient(childEnv, sc.basicImpl.net, resolveClientBinary(sc.basicImpl.clientBinary), []string{"--key", "key2"})
	if err != nil {
		return err
	}

	client2ErrCh := make(chan error)
	go func() {
		client2ErrCh <- cmd.Wait()
	}()
	return sc.wait(childEnv, cmd, client2ErrCh)
}
