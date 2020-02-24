package e2e

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// NodeShutdown is the keymanager restart scenario.
	NodeShutdown scenario.Scenario = newNodeShutdownImpl()
)

type nodeShutdownImpl struct {
	basicImpl
}

func newNodeShutdownImpl() scenario.Scenario {
	sc := &nodeShutdownImpl{
		basicImpl: *newBasicImpl("node-shutdown", "", nil),
	}
	return sc
}

func (sc *nodeShutdownImpl) Name() string {
	return "node-shutdown"
}

func (sc *nodeShutdownImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Make sure one of the compute nodes can terminate early.
	f.ComputeWorkers[0].AllowEarlyTermination = true
	return f, nil
}

func (sc *nodeShutdownImpl) Run(childEnv *env.Env) error {
	var err error

	if err = sc.net.Start(); err != nil {
		return err
	}

	sc.logger.Info("requesting node shutdown")
	computeWorker := sc.basicImpl.net.ComputeWorkers()[0]

	// Wait for the node to be ready since we didn't wait for any clients.
	nodeCtrl, err := oasis.NewController(computeWorker.SocketPath())
	if err != nil {
		return err
	}
	if err = nodeCtrl.WaitSync(context.Background()); err != nil {
		return err
	}

	args := []string{
		"control", "shutdown",
		"--log.level", "debug",
		"--address", "unix:" + computeWorker.SocketPath(),
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "control-shutdown", sc.basicImpl.net.Config().NodeBinary, args); err != nil {
		return errors.Wrap(err, "scenario/e2e/node_shutdown: send request failed")
	}

	// Wait for the node to exit.
	err = <-computeWorker.Exit()
	if err != env.ErrEarlyTerm {
		sc.logger.Error("compute worker exited with error",
			"err", err,
		)
		return err
	}

	// Try restarting it; it should shutdown by itself soon after.
	if err = computeWorker.Restart(); err != nil {
		return err
	}
	err = <-computeWorker.Exit()
	if err != env.ErrEarlyTerm {
		sc.logger.Error("compute worker exited with error on second run",
			"err", err,
		)
		return err
	}

	return nil
}
