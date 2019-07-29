package e2e

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/ekiden"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/scenario"
)

var (
	// KeymanagerRestart is the keymanager restart scenario.
	KeymanagerRestart scenario.Scenario = newKmRestartImpl()
)

type kmRestartImpl struct {
	basicImpl

	logger *logging.Logger
}

func newKmRestartImpl() scenario.Scenario {
	sc := &kmRestartImpl{
		basicImpl: basicImpl{
			clientBinary: "simple-keyvalue-enc-client",
			clientArgs:   []string{"--key", "key1"},
		},
		logger: logging.GetLogger("scenario/e2e/keymanager_restart"),
	}
	return sc
}

func (sc *kmRestartImpl) Name() string {
	return "keymanager-restart"
}

func (sc *kmRestartImpl) Fixture() (*ekiden.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Make sure the key manager node can be restarted.
	f.Keymanagers[0].Restartable = true
	return f, nil
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

	km := sc.basicImpl.net.Keymanager()

	// Restart the key manager.
	sc.logger.Info("restarting the key manager")
	if err = km.Restart(); err != nil {
		return err
	}

	// Wait for the key manager to be ready.
	sc.logger.Info("waiting for the key manager to become ready")
	kmCtrl, err := ekiden.NewController(km.SocketPath())
	if err != nil {
		return err
	}
	if err = kmCtrl.WaitReady(context.Background()); err != nil {
		return err
	}

	// Run the second client on a different key so that it will require
	// a second trip to the keymanager.
	sc.logger.Info("starting a second client to check if key manager works")
	cmd, err = startClient(childEnv, sc.basicImpl.net, sc.basicImpl.clientBinary, []string{"--key", "key2"})
	if err != nil {
		return err
	}

	client2ErrCh := make(chan error)
	go func() {
		client2ErrCh <- cmd.Wait()
	}()
	return sc.wait(childEnv, cmd, client2ErrCh)
}
